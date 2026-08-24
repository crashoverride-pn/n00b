/*
 * Whether the probe-versus-walk crossover holds on a sealed shard.
 *
 * Step counts say probing wins whenever the searches cost less than the walk.
 * On a mapped shard that arithmetic is missing something: a posting walk is
 * sequential and prefetches, while a binary search touches log2(df) pages
 * scattered across the mapping, any of which can fault. Counters cannot see
 * that, so this times the same queries against a hot shard and a sealed one.
 *
 * One shard, sealed after the hot timings are taken, so both halves measure
 * the same records rather than two separately generated sets.
 */

#include <stdint.h>
#include <time.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "text/strings/format.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/index.h"
#include "internal/rocs/plan_ir.h"
#include "internal/rocs/eval.h"
#include "rocs_test_support.h"

#define CHECK(expr)                                                                            \
    do {                                                                                       \
        n00b_require((expr), "test check failed: " #expr);                                     \
    } while (0)

// ---------------------------------------------------------------------------
// Sealed shards, where the crossover is least certain.
//
// The step counts say probing wins whenever the searches cost less than the
// walk. On a mapped shard that arithmetic is missing something: a posting walk
// is sequential and prefetches, while a binary search touches log2(df) pages
// scattered across the mapping, any of which can fault. Steps alone cannot see
// that, so this section times the same queries on a hot shard and a sealed one
// and prints both.
// ---------------------------------------------------------------------------

#define BIG        UINT64_C(5000)
#define BIG_WIDE   (BIG - 1)
#define BIG_MID    (BIG / 2)
#define BIG_NARROW (BIG / 15)

typedef struct {
    n00b_store_shard_t     *hot;
    n00b_store_map_t       *map;
    n00b_store_map_shard_t *sealed;
    n00b_store_index_t     *level;
    n00b_store_index_t     *trace;
    n00b_store_index_t     *band;
} big_t;

static big_t
big_sample(void)
{
    auto shard_r = n00b_store_shard_new(.shard_id  = UINT64_C(0xB16),
                                        .allocator = test_shard_allocator());
    CHECK(n00b_result_is_ok(shard_r));

    big_t b = {
        .hot   = n00b_result_get(shard_r),
        .level = index_of(r"level", N00B_STORE_INDEX_TERM),
        .trace = index_of(r"trace", N00B_STORE_INDEX_TERM),
        .band  = index_of(r"band", N00B_STORE_INDEX_TERM),
    };

    for (uint64_t i = 0; i < BIG; i++) {
        n00b_json_node_t *rec = n00b_json_object_new();
        n00b_json_object_put_n00b(
            rec,
            r"level",
            n00b_json_string_new_from_n00b(i < BIG_WIDE ? r"info" : r"error"));
        n00b_json_object_put_n00b(
            rec,
            r"trace",
            n00b_json_string_new_from_n00b(n00b_cformat("trace-«#»", (int64_t)i)));
        // Three bands: one wide, one narrow, one holding the rest, so the same
        // shard offers posting lists on both sides of the crossover.
        n00b_string_t *band = i < BIG_NARROW ? r"narrow" : (i < BIG_MID ? r"mid" : r"rest");
        n00b_json_object_put_n00b(rec, r"band", n00b_json_string_new_from_n00b(band));

        auto a_r = n00b_store_shard_append(b.hot, rec);
        CHECK(n00b_result_is_ok(a_r));
        uint64_t ord = n00b_result_get(a_r);
        CHECK(n00b_result_is_ok(n00b_store_index_add(b.level, b.hot, ord)));
        CHECK(n00b_result_is_ok(n00b_store_index_add(b.trace, b.hot, ord)));
        CHECK(n00b_result_is_ok(n00b_store_index_add(b.band, b.hot, ord)));
    }
    return b;
}

static void
big_seal(big_t *b)
{
    auto seal_r = n00b_store_shard_seal(b->hot, .seal_ts = 4242, .base_address = 0x900000u);
    CHECK(n00b_result_is_ok(seal_r));
    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    b->map      = n00b_result_get(map_r);
    auto root_r = n00b_store_map_root(b->map);
    CHECK(n00b_result_is_ok(root_r));
    b->sealed = n00b_result_get(root_r);
}

static n00b_plan_index_list_t *
big_indexes(big_t *b)
{
    n00b_plan_index_list_t *ix = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, b->level)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, b->trace)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, b->band)));
    return ix;
}

// A plan belongs to one shard (plan.h rule 4), and the hot shard and the image
// sealed from it are two. Each half plans from the counts of the shard it will
// run against.
static n00b_plan_node_t *
big_plan_hot(big_t *b, n00b_plan_predicate_t *pred)
{
    n00b_plan_index_list_t *ix = big_indexes(b);
    auto r = n00b_plan_build(pred, ix);
    CHECK(n00b_result_is_ok(r));
    CHECK(n00b_result_is_ok(n00b_plan_collect_hot(
        n00b_result_get(r), b->hot)));
    (void)n00b_plan_settle(n00b_result_get(r), b->hot->record_count);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_node_t *
big_plan_sealed(big_t *b, n00b_plan_predicate_t *pred)
{
    CHECK(b->sealed != nullptr);
    n00b_plan_index_list_t *ix = big_indexes(b);
    auto r = n00b_plan_build(pred, ix);
    CHECK(n00b_result_is_ok(r));
    CHECK(n00b_result_is_ok(n00b_plan_collect_mapped(
        n00b_result_get(r), b->sealed)));
    (void)n00b_plan_settle(n00b_result_get(r), n00b_result_get(_rocs_plan_mapped_record_count(b->sealed)));
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

typedef struct {
    n00b_plan_ordset_t *set;
    uint64_t            count;
    uint64_t            postings;
    uint64_t            probes;
    uint64_t            df_reads;
    uint64_t            ns;
} timed_t;

static void
check_same_members(n00b_plan_ordset_t *a, n00b_plan_ordset_t *b)
{
    for (uint64_t i = 0; i < BIG; i++) {
        auto in_a = n00b_plan_ordset_contains(a, i);
        auto in_b = n00b_plan_ordset_contains(b, i);
        CHECK(n00b_result_is_ok(in_a) && n00b_result_is_ok(in_b));
        CHECK(n00b_result_get(in_a) == n00b_result_get(in_b));
    }
}

#define REPEATS 5

static timed_t
time_run(big_t *b, n00b_plan_node_t *plan, bool sealed, bool cost)
{
    n00b_plan_cost_set_enabled(cost);

    // One untimed pass so neither side pays for cold pages the other warmed.
    if (sealed) {
        CHECK(n00b_result_is_ok(n00b_plan_exec_mapped(plan, b->sealed)));
    }
    else {
        CHECK(n00b_result_is_ok(n00b_plan_exec_hot(plan, b->hot)));
    }

#ifdef N00B_DEBUG
    n00b_plan_postings_walked_reset();
    n00b_plan_index_probes_reset();
    n00b_plan_index_df_reads_reset();
#endif

    // The fastest of the repeats, not their mean. Anything else running on the
    // machine can only ever make a sample slower, so a mean measures the load
    // as much as the code; the minimum is the closest thing here to the work
    // itself. This matters at this scale: these queries take milliseconds, and
    // a background build moves a mean by more than the difference under test.
    timed_t  out  = {};
    uint64_t best = UINT64_MAX;
    for (int i = 0; i < REPEATS; i++) {
        uint64_t start = now_ns();
        n00b_result_t(n00b_plan_ordset_t *) set_r;
        if (sealed) {
            set_r = n00b_plan_exec_mapped(plan, b->sealed);
        }
        else {
            set_r = n00b_plan_exec_hot(plan, b->hot);
        }
        uint64_t took = now_ns() - start;
        CHECK(n00b_result_is_ok(set_r));
        auto c_r = n00b_plan_ordset_count(n00b_result_get(set_r));
        CHECK(n00b_result_is_ok(c_r));
        out.count = n00b_result_get(c_r);
        out.set   = n00b_result_get(set_r);
        if (took < best) {
            best = took;
        }
    }
    out.ns = best;

#ifdef N00B_DEBUG
    out.postings = n00b_plan_postings_walked() / REPEATS;
    out.probes   = n00b_plan_index_probes() / REPEATS;
    out.df_reads = n00b_plan_index_df_reads() / REPEATS;
#endif
    return out;
}

#define SHAPES 5

static void
big_section(void)
{
    big_t b = big_sample();

    n00b_string_t *labels[SHAPES] = {
        r"narrow + widest",
        r"narrow + mid   ",
        r"narrow + short ",
        r"widest + widest",
        r"reversed       ",
    };
    n00b_plan_predicate_t *preds[SHAPES] = {
        group(eq(r"trace", r"trace-1500"), eq(r"level", r"info"), true),
        group(eq(r"trace", r"trace-1500"), eq(r"band", r"rest"), true),
        group(eq(r"trace", r"trace-50"), eq(r"band", r"narrow"), true),
        group(eq(r"level", r"info"), eq(r"band", r"rest"), true),
        group(eq(r"band", r"rest"), eq(r"level", r"info"), true),
    };

    n00b_plan_node_t *hot_plans[SHAPES];
    n00b_plan_node_t *sealed_plans[SHAPES];
    timed_t           hot_off[SHAPES], hot_on[SHAPES];
    timed_t           sea_off[SHAPES], sea_on[SHAPES];

    for (int i = 0; i < SHAPES; i++) {
        hot_plans[i] = big_plan_hot(&b, preds[i]);
        hot_off[i]   = time_run(&b, hot_plans[i], false, false);
        hot_on[i]    = time_run(&b, hot_plans[i], false, true);
    }

    // Hot execution refuses a sealed shard, so every hot run happens first.
    // The sealed plans cannot be built before this either: their counts come
    // out of the image it produces.
    big_seal(&b);

    for (int i = 0; i < SHAPES; i++) {
        sealed_plans[i] = big_plan_sealed(&b, preds[i]);
        sea_off[i]      = time_run(&b, sealed_plans[i], true, false);
        sea_on[i]       = time_run(&b, sealed_plans[i], true, true);
    }

    n00b_printf(" ");
    n00b_printf("hot vs sealed, «#» records, cost off -> on:", (int64_t)BIG);

    for (int i = 0; i < SHAPES; i++) {
        // Members, not just how many. Two sets of the same size are not the
        // same answer, and the sealed and hot halves must agree on which rows
        // matched, not merely on the count.
        // One posting count per indexed child of a group, and none at all
        // without ordering. This is the cost of deciding, and it is the number
        // that can rise while every other counter stays flat, so a shape that
        // saves nothing still has its decision cost pinned here.
#ifdef N00B_DEBUG
        CHECK(hot_off[i].df_reads == 0);
        CHECK(sea_off[i].df_reads == 0);
        CHECK(hot_on[i].df_reads <= 4);
        CHECK(sea_on[i].df_reads <= 4);
#endif

        check_same_members(hot_off[i].set, hot_on[i].set);
        check_same_members(sea_off[i].set, sea_on[i].set);
        check_same_members(hot_off[i].set, sea_off[i].set);

        n00b_printf("  «#»  matched=«#»", labels[i], (int64_t)hot_on[i].count);
        n00b_printf(
            "      hot     «#»ns->«#»ns  postings «#»->«#»  probes «#»->«#»  dfreads «#»",
            (int64_t)hot_off[i].ns,
            (int64_t)hot_on[i].ns,
            (int64_t)hot_off[i].postings,
            (int64_t)hot_on[i].postings,
            (int64_t)hot_off[i].probes,
            (int64_t)hot_on[i].probes,
            (int64_t)hot_on[i].df_reads);
        n00b_printf(
            "      sealed  «#»ns->«#»ns  postings «#»->«#»  probes «#»->«#»  dfreads «#»",
            (int64_t)sea_off[i].ns,
            (int64_t)sea_on[i].ns,
            (int64_t)sea_off[i].postings,
            (int64_t)sea_on[i].postings,
            (int64_t)sea_off[i].probes,
            (int64_t)sea_on[i].probes,
            (int64_t)sea_on[i].df_reads);
    }

    CHECK(n00b_result_is_ok(n00b_store_map_close(b.map)));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    big_section();

    n00b_shutdown();
    return 0;
}
