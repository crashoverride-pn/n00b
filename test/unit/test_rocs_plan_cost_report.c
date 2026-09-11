/*
 * What cost-ordered execution saves, per query shape, on a shard big enough
 * for the numbers to mean something.
 *
 * Every shape runs twice against the same plan and the same shard, once with
 * ordering off and once on. The answers have to match; the work does not. The
 * table it prints is the whole scorecard, including the shapes where the
 * saving is nothing, which are the majority.
 */

#include <stdint.h>

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

#define RECORDS UINT64_C(2000)
#define BROAD   (RECORDS - 1)

typedef struct {
    n00b_store_shard_t *shard;
    n00b_store_index_t *level;
    n00b_store_index_t *trace;
    n00b_store_index_t *kind;
    n00b_store_index_t *message;
} sample_t;

static sample_t
sample(void)
{
    auto shard_r = n00b_store_shard_new(.shard_id  = UINT64_C(0xBEEF),
                                        .allocator = test_shard_allocator());
    CHECK(n00b_result_is_ok(shard_r));

    sample_t s = {
        .shard   = n00b_result_get(shard_r),
        .level   = index_of(r"level", N00B_STORE_INDEX_TERM),
        .trace   = index_of(r"trace", N00B_STORE_INDEX_TERM),
        .kind    = index_of(r"kind", N00B_STORE_INDEX_TERM),
        .message = index_of(r"message", N00B_STORE_INDEX_NGRAM),
    };

    for (uint64_t i = 0; i < RECORDS; i++) {
        n00b_json_node_t *rec = n00b_json_object_new();
        n00b_json_object_put_n00b(
            rec,
            r"level",
            n00b_json_string_new_from_n00b(i < BROAD ? r"info" : r"error"));
        n00b_json_object_put_n00b(rec, r"kind", n00b_json_string_new_from_n00b(r"log"));
        n00b_json_object_put_n00b(
            rec,
            r"trace",
            n00b_json_string_new_from_n00b(n00b_cformat("trace-«#»", (int64_t)i)));
        n00b_json_object_put_n00b(
            rec,
            r"message",
            n00b_json_string_new_from_n00b(n00b_cformat("common prefix «#»", (int64_t)i)));

        auto a_r = n00b_store_shard_append(s.shard, rec);
        CHECK(n00b_result_is_ok(a_r));
        uint64_t ord = n00b_result_get(a_r);

        CHECK(n00b_result_is_ok(n00b_store_index_add(s.level, s.shard, ord)));
        CHECK(n00b_result_is_ok(n00b_store_index_add(s.trace, s.shard, ord)));
        CHECK(n00b_result_is_ok(n00b_store_index_add(s.kind, s.shard, ord)));
        CHECK(n00b_result_is_ok(n00b_store_index_add(s.message, s.shard, ord)));
    }
    return s;
}

static n00b_plan_node_t *
plan_of(sample_t *s, n00b_plan_predicate_t *pred)
{
    n00b_plan_index_list_t *ix = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->level)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->trace)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->kind)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->message)));
    auto r = n00b_plan_build(pred, ix);
    CHECK(n00b_result_is_ok(r));
    CHECK(n00b_result_is_ok(n00b_plan_collect_hot(
        n00b_result_get(r), s->shard)));
    (void)n00b_plan_settle(n00b_result_get(r), s->shard->record_count);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

typedef struct {
    n00b_plan_ordset_t *set;
    uint64_t            count;
    uint64_t            records;
    uint64_t            postings;
    uint64_t            probes;
} run_t;

static run_t
measure(n00b_plan_node_t *plan, n00b_store_shard_t *shard, bool cost)
{
    n00b_plan_cost_set_enabled(cost);
#ifdef N00B_DEBUG
    n00b_plan_records_scanned_reset();
    n00b_plan_postings_walked_reset();
    n00b_plan_index_probes_reset();
#endif
    auto set_r = n00b_plan_exec_hot(plan, shard);
    CHECK(n00b_result_is_ok(set_r));
    auto c_r = n00b_plan_ordset_count(n00b_result_get(set_r));
    CHECK(n00b_result_is_ok(c_r));

    run_t out = {.set = n00b_result_get(set_r), .count = n00b_result_get(c_r)};
#ifdef N00B_DEBUG
    out.records  = n00b_plan_records_scanned();
    out.postings = n00b_plan_postings_walked();
    out.probes   = n00b_plan_index_probes();
#endif
    return out;
}

static void
report(n00b_string_t *label, sample_t *s, n00b_plan_predicate_t *pred)
{
    n00b_plan_node_t *plan = plan_of(s, pred);
    run_t             off  = measure(plan, s->shard, false);
    run_t             on   = measure(plan, s->shard, true);

    // The invariant, checked on every shape rather than asserted once. Equal
    // cardinality is not the claim: ordering may not change which records
    // match, and two different sets of the same size would satisfy a count
    // comparison while breaking exactly what this is here to protect.
    CHECK(off.count == on.count);
    for (uint64_t i = 0; i < RECORDS; i++) {
        auto in_off = n00b_plan_ordset_contains(off.set, i);
        auto in_on  = n00b_plan_ordset_contains(on.set, i);
        CHECK(n00b_result_is_ok(in_off) && n00b_result_is_ok(in_on));
        CHECK(n00b_result_get(in_off) == n00b_result_get(in_on));
    }

    n00b_printf("  «#» matched=«#»  postings «#»->«#»  probes «#»->«#»  records «#»->«#»",
                label,
                (int64_t)on.count,
                (int64_t)off.postings,
                (int64_t)on.postings,
                (int64_t)off.probes,
                (int64_t)on.probes,
                (int64_t)off.records,
                (int64_t)on.records);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    sample_t s = sample();

    n00b_printf("cost-ordered execution, «#» records, off -> on:", (int64_t)RECORDS);

    report(r"AND broad + absent  ",
           &s,
           group(eq(r"level", r"info"), eq(r"trace", r"nope"), true));
    report(r"AND broad + narrow  ",
           &s,
           group(eq(r"level", r"info"), eq(r"trace", r"trace-1234"), true));
    report(r"AND broad + broad   ",
           &s,
           group(eq(r"level", r"info"), eq(r"kind", r"log"), true));
    report(r"AND narrow + broad  ",
           &s,
           group(eq(r"level", r"error"), eq(r"kind", r"log"), true));
    report(r"OR  narrow + broad  ",
           &s,
           group(eq(r"level", r"error"), eq(r"kind", r"log"), false));
    report(r"OR  broad + narrow  ",
           &s,
           group(eq(r"kind", r"log"), eq(r"level", r"error"), false));

    auto prefix_r = n00b_plan_predicate_prefix(target(r"message"), r"com");
    CHECK(n00b_result_is_ok(prefix_r));
    report(r"prefix, shard-wide  ", &s, n00b_result_get(prefix_r));

    auto rare_r = n00b_plan_predicate_prefix(target(r"message"), r"zzz");
    CHECK(n00b_result_is_ok(rare_r));
    report(r"prefix, no match    ", &s, n00b_result_get(rare_r));

    n00b_shutdown();
    return 0;
}
