/* test/unit/bench_rocs_query_ab.c - what this branch did to real queries.
 *
 * One binary, both arms, switched at runtime. The alternative is compiling the
 * same source twice and diffing, which measures the machine as much as the
 * code: between two runs of one binary this laptop drifts by more than several
 * of the effects below are worth.
 *
 * Work counters lead, wall time follows. Records scanned, postings walked and
 * shards opened are deterministic -- the same query over the same store gives
 * the same numbers on an idle machine and a loaded one -- so they say what
 * changed without a quiet room to say it in. Time is reported beside them
 * because it is what anybody actually feels, not because it is the better
 * measurement.
 *
 * Three switches, matching the three things the branch changed:
 *
 *   rewrite      n00b_plan_build(.rewrite)         predicate rewriting
 *   zones        n00b_store_zone_maps_enabled      per-shard value bounds
 *   cost         n00b_plan_cost_enabled            operand and leaf ordering
 *
 * Zone maps are decided at ingest, so that arm rebuilds its store; the other
 * two are decided per query and reuse one.
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

#include "internal/rocs/plan_ir.h"
#include "internal/rocs/eval.h"
#include "internal/rocs/index.h"
#include "internal/rocs/store.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "bench check failed: " #expr);                    \
    } while (0)

#ifndef N00B_DEBUG
#error "bench_rocs_query_ab needs N00B_DEBUG for the work counters"
#endif

static uint64_t shards       = 8;
static uint64_t per_shard    = 200;
static uint64_t repetitions  = 40;

static uint64_t
env_u64(const char *name, uint64_t fallback)
{
    const char *v = getenv(name);
    if (v == nullptr || *v == '\0') {
        return fallback;
    }
    return (uint64_t)strtoull(v, nullptr, 10);
}

// ---------------------------------------------------------------------------

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

// Each shard holds a distinct window of `ts`, which is what a store fed by an
// append-only event stream looks like and what makes a range prunable at all.
// `level` is skewed the way log levels are; `trace` is unique per record.
static n00b_store_t *
build_store(bool zones)
{
    n00b_store_zone_maps_set_enabled(zones);

    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_schema_t *schema = n00b_result_get(schema_r);

    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"ts")));
    CHECK(n00b_result_is_ok(
        n00b_store_schema_add_field(schema,
                                    r"level",
                                    .index_kind = N00B_STORE_INDEX_TERM)));
    CHECK(n00b_result_is_ok(
        n00b_store_schema_add_field(schema,
                                    r"trace",
                                    .index_kind = N00B_STORE_INDEX_TERM)));
    CHECK(n00b_result_is_ok(
        n00b_store_schema_add_field(schema,
                                    r"kind",
                                    .index_kind = N00B_STORE_INDEX_TERM)));

    auto store_r = n00b_store_open_vfs(new_memory_vfs(), r"/rocs", schema);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    for (uint64_t sh = 0; sh < shards; sh++) {
        for (uint64_t i = 0; i < per_shard; i++) {
            int64_t           id     = (int64_t)(sh * per_shard + i);
            n00b_json_node_t *record = n00b_json_object_new();
            n00b_json_object_put_n00b(record, r"ts", n00b_json_int_new(id));
            n00b_json_object_put_n00b(
                record,
                r"level",
                n00b_json_string_new_from_n00b(i % 50 == 0 ? r"error"
                                                           : r"info"));
            n00b_json_object_put_n00b(
                record,
                r"trace",
                n00b_json_string_new_from_n00b(
                    n00b_cformat("trace-«#»", id)));
            n00b_json_object_put_n00b(record,
                                      r"kind",
                                      n00b_json_string_new_from_n00b(r"log"));
            CHECK(n00b_result_is_ok(n00b_store_ingest(store, record)));
        }
        CHECK(n00b_result_is_ok(
            n00b_store_seal_hot_shard(store, .seal_ts = 1000 + sh)));
    }

    n00b_store_zone_maps_set_enabled(true);
    return store;
}

// ---------------------------------------------------------------------------
// Predicate shapes.

static n00b_plan_target_t *
field(n00b_string_t *name)
{
    auto r = n00b_plan_target_field(name);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_value_t
jstr(n00b_string_t *s)
{
    return n00b_variant_set(n00b_plan_value_t,
                            n00b_json_node_t *,
                            n00b_json_string_new_from_n00b(s));
}

static n00b_plan_value_t
jint(int64_t v)
{
    return n00b_variant_set(n00b_plan_value_t,
                            n00b_json_node_t *,
                            n00b_json_int_new(v));
}

static n00b_plan_predicate_t *
ok(n00b_result_t(n00b_plan_predicate_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
eq_s(n00b_string_t *f, n00b_string_t *v)
{
    return ok(n00b_plan_predicate_eq(field(f), jstr(v)));
}

static n00b_plan_predicate_t *
rng(n00b_string_t *f, int64_t lo, int64_t hi)
{
    return ok(n00b_plan_predicate_range(field(f), jint(lo), jint(hi)));
}

static n00b_plan_predicate_t *
exists_of(n00b_string_t *f)
{
    return ok(n00b_plan_predicate_exists(field(f)));
}

static n00b_plan_predicate_t *
grp(bool conj, n00b_plan_predicate_t **kids, size_t n)
{
    n00b_plan_predicate_list_t *l = n00b_plan_predicate_list_new();
    for (size_t i = 0; i < n; i++) {
        CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(l, kids[i])));
    }
    return ok(conj ? n00b_plan_predicate_and(l) : n00b_plan_predicate_or(l));
}

#define AND(...)                                                               \
    grp(true,                                                                  \
        (n00b_plan_predicate_t *[]){__VA_ARGS__},                              \
        sizeof((n00b_plan_predicate_t *[]){__VA_ARGS__})                       \
            / sizeof(n00b_plan_predicate_t *))
#define OR(...)                                                                \
    grp(false,                                                                 \
        (n00b_plan_predicate_t *[]){__VA_ARGS__},                              \
        sizeof((n00b_plan_predicate_t *[]){__VA_ARGS__})                       \
            / sizeof(n00b_plan_predicate_t *))

typedef n00b_plan_predicate_t *(*shape_fn)(void);

static n00b_plan_predicate_t *q_range_narrow(void)
{
    return rng(r"ts", 210, 260);
}
static n00b_plan_predicate_t *q_range_whole(void)
{
    return rng(r"ts", 0, 100000);
}
static n00b_plan_predicate_t *q_range_miss(void)
{
    return rng(r"ts", 500000, 600000);
}
static n00b_plan_predicate_t *q_dup_leaf(void)
{
    return AND(eq_s(r"level", r"error"), eq_s(r"level", r"error"));
}
static n00b_plan_predicate_t *q_or_of_eq(void)
{
    return OR(eq_s(r"level", r"error"), eq_s(r"level", r"info"));
}
static n00b_plan_predicate_t *q_factorable(void)
{
    return OR(AND(eq_s(r"kind", r"log"), eq_s(r"level", r"error")),
              AND(eq_s(r"kind", r"log"), eq_s(r"trace", r"trace-7")));
}
static n00b_plan_predicate_t *q_contradiction(void)
{
    return AND(eq_s(r"level", r"error"),
               ok(n00b_plan_predicate_not(eq_s(r"level", r"error"))));
}
static n00b_plan_predicate_t *q_and_ranges(void)
{
    return AND(rng(r"ts", 200, 900), rng(r"ts", 210, 260));
}
static n00b_plan_predicate_t *q_or_ranges(void)
{
    return OR(rng(r"ts", 210, 240), rng(r"ts", 230, 260));
}
static n00b_plan_predicate_t *q_exists_then_eq(void)
{
    return AND(exists_of(r"level"), eq_s(r"trace", r"trace-7"));
}
static n00b_plan_predicate_t *q_nested_scan(void)
{
    return AND(eq_s(r"level", r"error"),
               AND(OR(exists_of(r"kind"), eq_s(r"trace", r"trace-7")),
                   eq_s(r"trace", r"trace-3")));
}
static n00b_plan_predicate_t *q_plain_eq(void)
{
    return eq_s(r"trace", r"trace-7");
}

typedef struct {
    const char *name;
    shape_fn    build;
} shape_t;

static shape_t shapes[] = {
    {"range, one shard window",     q_range_narrow},
    {"range, whole store",          q_range_whole},
    {"range, matches nothing",      q_range_miss},
    {"AND with a repeated leaf",    q_dup_leaf},
    {"OR of equalities, one field", q_or_of_eq},
    {"OR with a shared conjunct",   q_factorable},
    {"AND of a leaf and its NOT",   q_contradiction},
    {"AND of overlapping ranges",   q_and_ranges},
    {"OR of overlapping ranges",    q_or_ranges},
    {"exists AND a rare equality",  q_exists_then_eq},
    {"nested group over a scan",    q_nested_scan},
    {"a plain equality",            q_plain_eq},
};

// ---------------------------------------------------------------------------

typedef struct {
    uint64_t shards_opened;
    uint64_t records;
    uint64_t postings;
    uint64_t matched;
    int64_t  ns;
} run_t;

static run_t
run_shape(n00b_store_t *store, shape_fn build, bool rewrite, bool cost)
{
    n00b_plan_cost_set_enabled(cost);

    // Warm once so the numbers are not a first-touch artifact, then measure
    // the best of several: interference only ever adds.
    run_t out = {.ns = INT64_MAX};

    n00b_plan_rewrite_set_enabled(rewrite);

    for (uint64_t i = 0; i < repetitions; i++) {
        n00b_plan_predicate_t *predicate = build();

        n00b_plan_records_scanned_reset();
        n00b_plan_postings_walked_reset();

        // The store's own descriptors. An empty list leaves every leaf on a
        // record scan, which measures a store with no indexes at all rather
        // than this one.
        auto ix_r = n00b_store_plan_indexes_for_query(store);
        CHECK(n00b_result_is_ok(ix_r));

        int64_t start = n00b_ns_timestamp();
        auto results_r = n00b_plan_store_sealed(store,
                                                predicate,
                                                n00b_result_get(ix_r));
        int64_t ns = n00b_ns_timestamp() - start;
        CHECK(n00b_result_is_ok(results_r));

        n00b_plan_shard_result_list_t *results = n00b_result_get(results_r);
        auto cnt_r = n00b_plan_shard_result_count(results);
        CHECK(n00b_result_is_ok(cnt_r));
        uint64_t opened = n00b_result_get(cnt_r);

        uint64_t matched = 0;
        for (uint64_t s = 0; s < opened; s++) {
            auto at_r = n00b_plan_shard_result_at(results, s);
            CHECK(n00b_result_is_ok(at_r));
            auto opt = n00b_result_get(at_r);
            if (!n00b_option_is_set(opt)) {
                continue;
            }
            auto ord_r = n00b_plan_shard_result_ordinals(n00b_option_get(opt));
            CHECK(n00b_result_is_ok(ord_r));
            auto n_r = n00b_plan_ordset_count(n00b_result_get(ord_r));
            CHECK(n00b_result_is_ok(n_r));
            matched += n00b_result_get(n_r);
        }

        if (ns < out.ns) {
            out.ns = ns;
        }
        out.shards_opened = opened;
        out.records       = n00b_plan_records_scanned();
        out.postings      = n00b_plan_postings_walked();
        out.matched       = matched;
    }

    n00b_plan_cost_set_enabled(true);
    n00b_plan_rewrite_set_enabled(true);
    return out;
}

static void
report(const char *label, run_t off, run_t on)
{
    CHECK(off.matched == on.matched);

    n00b_printf(
        "  [|#|]\n"
        "      shards [|#|] -> [|#|]   records [|#|] -> [|#|]   "
        "postings [|#|] -> [|#|]\n"
        "      us [|#|] -> [|#|]   (matched [|#|])",
        n00b_string_from_cstr(label),
        (int64_t)off.shards_opened,
        (int64_t)on.shards_opened,
        (int64_t)off.records,
        (int64_t)on.records,
        (int64_t)off.postings,
        (int64_t)on.postings,
        (int64_t)(off.ns / 1000),
        (int64_t)(on.ns / 1000),
        (int64_t)on.matched);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    shards      = env_u64("ROCS_BENCH_SHARDS", 8);
    per_shard   = env_u64("ROCS_BENCH_RECORDS", 200);
    repetitions = env_u64("ROCS_BENCH_ROUNDS", 40);

    n00b_printf("store: [|#|] shards x [|#|] records, best of [|#|]",
                (int64_t)shards,
                (int64_t)per_shard,
                (int64_t)repetitions);

    // Zone maps are an ingest-time decision, so each arm needs its own store.
    n00b_store_t *with    = build_store(true);
    n00b_store_t *without = build_store(false);

    n00b_printf("\nzone maps off -> on (same queries, same answers):");
    for (size_t i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
        run_t off = run_shape(without, shapes[i].build, true, true);
        run_t on  = run_shape(with, shapes[i].build, true, true);
        report(shapes[i].name, off, on);
    }

    n00b_printf("\nrewriting off -> on (zone maps and cost on for both):");
    for (size_t i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
        run_t off = run_shape(with, shapes[i].build, false, true);
        run_t on  = run_shape(with, shapes[i].build, true, true);
        report(shapes[i].name, off, on);
    }

    n00b_printf("\ncost ordering off -> on (zone maps and rewriting on):");
    for (size_t i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
        run_t off = run_shape(with, shapes[i].build, true, false);
        run_t on  = run_shape(with, shapes[i].build, true, true);
        report(shapes[i].name, off, on);
    }

    n00b_shutdown();
    return 0;
}
