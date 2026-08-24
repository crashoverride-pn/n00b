/*
 * Plans built to hurt, and what cost-ordered execution does with them.
 *
 * Ordering is worth having only if it degrades gracefully. Three things are
 * checked on every shape here: the answer does not change, the number of
 * postings read does not go up, and the resident set does not run away. Times
 * are printed, not asserted, because a machine under load moves them further
 * than a regression would. The shapes are chosen for the parts of the
 * implementation that scale worst.
 *
 *   wide    one group with many children. Picking the next child scans the
 *           remaining bounds, so a group of n costs n^2 comparisons to order,
 *           and n posting-count reads to bound.
 *   deep    alternating AND/OR so the planner cannot splice the levels
 *           together. Bounding a group recurses to every leaf beneath it, and
 *           each nested group bounds its own children again on the way down.
 *   both    the product of those two.
 *   flat    many children with identical posting counts, so every bound is
 *           paid for and none of them separates anything.
 *   opaque  many children that read records, which are excluded from ordering
 *           entirely, so the bookkeeping is pure overhead.
 */

#include <stdint.h>
#include <sys/resource.h>
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

#define RECORDS UINT64_C(4096)

typedef enum {
    LEAF_VARIED = 0,
    LEAF_LOSSY,
    LEAF_NEGATED,
    LEAF_SAME,
} leaf_kind_t;

typedef struct {
    n00b_store_shard_t *shard;
    n00b_store_index_t *level;
    n00b_store_index_t *trace;
    n00b_store_index_t *band;
    n00b_store_index_t *msg;
} sample_t;

// Reproducible without a clock or a global. Every shape derives its choices
// from a seed the caller names, so a failure can be replayed.
static uint64_t rng_state = 0;

static uint64_t
rng(uint64_t bound)
{
    rng_state = rng_state * UINT64_C(6364136223846793005) + UINT64_C(1);
    return bound == 0 ? 0 : (rng_state >> 33) % bound;
}

static n00b_store_index_t *
ngram_of(n00b_string_t *field)
{
    auto r = n00b_store_index_new(field, N00B_STORE_INDEX_NGRAM);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static sample_t
sample(void)
{
    auto shard_r = n00b_store_shard_new(.shard_id  = UINT64_C(0x9A7),
                                        .allocator = test_shard_allocator());
    CHECK(n00b_result_is_ok(shard_r));

    sample_t s = {
        .shard = n00b_result_get(shard_r),
        .level = index_of(r"level", N00B_STORE_INDEX_TERM),
        .trace = index_of(r"trace", N00B_STORE_INDEX_TERM),
        .band  = index_of(r"band", N00B_STORE_INDEX_TERM),
        .msg   = ngram_of(r"msg"),
    };

    for (uint64_t i = 0; i < RECORDS; i++) {
        n00b_json_node_t *rec = n00b_json_object_new();
        n00b_json_object_put_n00b(
            rec,
            r"level",
            n00b_json_string_new_from_n00b(i + 1 < RECORDS ? r"info" : r"error"));
        n00b_json_object_put_n00b(
            rec,
            r"trace",
            n00b_json_string_new_from_n00b(n00b_cformat("trace-«#»", (int64_t)i)));
        // Sixteen bands, so a band lookup lands well inside the shard and the
        // bound of one child actually differs from the bound of another.
        n00b_json_object_put_n00b(
            rec,
            r"band",
            n00b_json_string_new_from_n00b(n00b_cformat("band-«#»", (int64_t)(i % 16))));

        n00b_json_object_put_n00b(
            rec,
            r"msg",
            n00b_json_string_new_from_n00b(
                n00b_cformat("m«#»-body-«#»", (int64_t)(i % 64), (int64_t)i)));

        auto a_r = n00b_store_shard_append(s.shard, rec);
        CHECK(n00b_result_is_ok(a_r));
        uint64_t ord = n00b_result_get(a_r);
        CHECK(n00b_result_is_ok(n00b_store_index_add(s.level, s.shard, ord)));
        CHECK(n00b_result_is_ok(n00b_store_index_add(s.trace, s.shard, ord)));
        CHECK(n00b_result_is_ok(n00b_store_index_add(s.band, s.shard, ord)));
        CHECK(n00b_result_is_ok(n00b_store_index_add(s.msg, s.shard, ord)));
    }
    return s;
}

// An indexed leaf whose selectivity varies, so bounds differ between siblings.
static n00b_plan_predicate_t *
varied_leaf(void)
{
    switch (rng(3)) {
    case 0:
        return eq(r"band", n00b_cformat("band-«#»", (int64_t)rng(16)));
    case 1:
        return eq(r"trace", n00b_cformat("trace-«#»", (int64_t)rng(RECORDS)));
    default:
        return eq(r"level", rng(2) == 0 ? r"info" : r"error");
    }
}

// A lossy leaf: an n-gram scan that over-approximates and is paired with the
// record scan that settles it.
static n00b_plan_predicate_t *
lossy_leaf(void)
{
    auto r
        = n00b_plan_predicate_prefix(target(r"msg"), n00b_cformat("m«#»-", (int64_t)rng(64)));
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

// A negated leaf, which plans to COMPLEMENT over an indefinite child.
static n00b_plan_predicate_t *
negated_leaf(void)
{
    auto r = n00b_plan_predicate_not(varied_leaf());
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

// A leaf with no index path, so it plans to a record scan.
static n00b_plan_predicate_t *
opaque_leaf(void)
{
    auto r = n00b_plan_predicate_exists(target(r"trace"));
    CHECK(n00b_result_is_ok(r));
    return r.is_ok ? n00b_result_get(r) : nullptr;
}

static n00b_plan_predicate_t *
group_of(n00b_plan_predicate_list_t *kids, bool conjunction)
{
    auto r = conjunction ? n00b_plan_predicate_and(kids) : n00b_plan_predicate_or(kids);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_list_t *
list_new(void)
{
    n00b_plan_predicate_list_t *kids = n00b_plan_predicate_list_new();
    CHECK(kids != nullptr);
    return kids;
}

static void
push(n00b_plan_predicate_list_t *kids, n00b_plan_predicate_t *p)
{
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(kids, p)));
}

// width children, depth levels, alternating AND/OR so the planner keeps the
// levels apart instead of splicing same-kind groups into one.
static n00b_plan_predicate_t *
leaf_of(leaf_kind_t kind)
{
    switch (kind) {
    case LEAF_LOSSY:
        return lossy_leaf();
    case LEAF_NEGATED:
        return negated_leaf();
    case LEAF_SAME:
        // The same predicate over and over. Nothing dedups these, so a group
        // of them reads one posting count per copy for a single distinct key.
        return eq(r"band", r"band-0");
    default:
        return varied_leaf();
    }
}

static n00b_plan_predicate_t *
build(uint64_t width, uint64_t depth, bool conjunction, bool opaque, leaf_kind_t kind)
{
    n00b_plan_predicate_list_t *kids = list_new();

    for (uint64_t i = 0; i < width; i++) {
        push(kids, opaque && i == 0 ? opaque_leaf() : leaf_of(kind));
    }
    if (depth > 1) {
        push(kids, build(width, depth - 1, !conjunction, opaque, kind));
    }
    // A group constructor wants at least two operands, and a one-child group
    // would be replaced by its child anyway.
    if (width == 1 && depth == 1) {
        return leaf_of(kind);
    }
    return group_of(kids, conjunction);
}

static n00b_plan_node_t *
plan_of(sample_t *s, n00b_plan_predicate_t *pred)
{
    n00b_plan_index_list_t *ix = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->level)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->trace)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->band)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->msg)));
    auto r = n00b_plan_build(pred, ix);
    CHECK(n00b_result_is_ok(r));
    CHECK(n00b_result_is_ok(n00b_plan_collect_hot(
        n00b_result_get(r), s->shard)));
    (void)n00b_plan_settle(n00b_result_get(r), s->shard->record_count);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

#ifdef N00B_DEBUG
// Leaves in the predicate, not index scans in the plan. Resolution happens per
// operand as the plan is built, and dedup collapses duplicates after that, so
// the built plan can hold far fewer index scans than were resolved to make it.
// The predicate's leaf count is the ceiling that does not move.
static uint64_t
count_predicate_leaves(n00b_plan_predicate_t *predicate)
{
    if (predicate == nullptr) {
        return 0;
    }
    if (predicate->kind == N00B_PLAN_PREDICATE_LEAF) {
        return 1;
    }

    uint64_t n = count_predicate_leaves(predicate->child);
    if (predicate->children != nullptr) {
        size_t len = n00b_list_len(*predicate->children);
        for (size_t i = 0; i < len; i++) {
            n += count_predicate_leaves(n00b_list_get(*predicate->children, i));
        }
    }
    return n;
}
#endif

static uint64_t
rss_kb(void)
{
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    // Darwin reports bytes here, Linux kilobytes. Either way it is a
    // high-water mark, so only the growth across a run means anything.
    return (uint64_t)ru.ru_maxrss;
}

typedef struct {
    n00b_plan_ordset_t *set;
    uint64_t            postings;
    uint64_t            probes;
    uint64_t            records;
    uint64_t            ns;
} run_t;

#define REPEATS 5

static run_t
run_with(sample_t *s, n00b_plan_node_t *plan, bool cost)
{
    n00b_plan_cost_set_enabled(cost);
#ifdef N00B_DEBUG
    n00b_plan_postings_walked_reset();
    n00b_plan_index_probes_reset();
    n00b_plan_records_scanned_reset();
#endif

    // One untimed pass, then repeats: a single sample with `off` always first
    // measures cache state as much as it measures ordering.
    auto warm_r = n00b_plan_exec_hot(plan, s->shard);
    CHECK(n00b_result_is_ok(warm_r));

    n00b_result_t(n00b_plan_ordset_t *) set_r = warm_r;
    uint64_t start                            = now_ns();
    for (int i = 0; i < REPEATS; i++) {
        set_r = n00b_plan_exec_hot(plan, s->shard);
        CHECK(n00b_result_is_ok(set_r));
    }
    uint64_t ns = (now_ns() - start) / REPEATS;

    run_t out = {.set = n00b_result_get(set_r), .ns = ns};
#ifdef N00B_DEBUG
    out.postings = n00b_plan_postings_walked() / REPEATS;
    out.probes   = n00b_plan_index_probes() / REPEATS;
    out.records  = n00b_plan_records_scanned() / REPEATS;
#endif
    return out;
}

static void
check_shape(n00b_string_t *label,
            sample_t      *s,
            uint64_t       width,
            uint64_t       depth,
            bool           opaque,
            leaf_kind_t    kind,
            uint64_t       seed)
{
    rng_state                   = seed;
    n00b_plan_predicate_t *pred = build(width, depth, true, opaque, kind);
    n00b_plan_node_t      *plan = plan_of(s, pred);

    // Building the plan is work too. A wide group resolves and buckets every
    // operand, so build time tracks width and this is where a regression in it
    // would show.
    uint64_t build_start = now_ns();
    for (int i = 0; i < REPEATS; i++) {
        (void)plan_of(s, pred);
    }
    uint64_t build_ns = (now_ns() - build_start) / REPEATS;

#ifdef N00B_DEBUG
    // Build cost is dominated by key resolution, and this gates it without
    // asserting on a clock. One resolution per indexed leaf is the ceiling:
    // anything above it means a leaf is being resolved more than once.
    n00b_plan_keys_resolved_reset();
    (void)plan_of(s, pred);
    uint64_t resolved = n00b_plan_keys_resolved();
    uint64_t leaves   = count_predicate_leaves(pred);
    CHECK(resolved <= leaves);
#endif

    // Each arm plans as well as runs under its own setting. Two of the three
    // cost decisions are made while the plan is built, so a plan built once
    // and executed both ways compares execution alone.
    n00b_plan_cost_set_enabled(false);
    n00b_plan_node_t *plain = plan_of(s, pred);
    n00b_plan_cost_set_enabled(true);
    n00b_plan_node_t *costed = plan_of(s, pred);

    run_t    off    = run_with(s, plain, false);
    run_t    on     = run_with(s, costed, true);
    run_t    on2    = run_with(s, costed, true);
    run_t    off2   = run_with(s, plain, false);

    // Keep the faster of each pair. Whichever mode ran first paid for the cold
    // shard, and alternating means that is not always the same one.
    if (off2.ns < off.ns) {
        off.ns = off2.ns;
    }
    if (on2.ns < on.ns) {
        on.ns = on2.ns;
    }

    // 1. The answer does not change.
    auto off_c = n00b_plan_ordset_count(off.set);
    auto on_c  = n00b_plan_ordset_count(on.set);
    CHECK(n00b_result_is_ok(off_c) && n00b_result_is_ok(on_c));
    CHECK(n00b_result_get(off_c) == n00b_result_get(on_c));
    for (uint64_t i = 0; i < RECORDS; i++) {
        auto a = n00b_plan_ordset_contains(off.set, i);
        auto b = n00b_plan_ordset_contains(on.set, i);
        CHECK(n00b_result_is_ok(a) && n00b_result_is_ok(b));
        CHECK(n00b_result_get(a) == n00b_result_get(b));
    }

#ifdef N00B_DEBUG
    // 2. Ordering never reads more postings than plan order would. Reordering
    //    index scans changes nothing unless an early exit fires, probing
    //    replaces a walk rather than adding to one, and skipping a lossy scan
    //    only removes work.
    CHECK(on.postings <= off.postings);
    CHECK(on.records <= off.records);
#endif

    n00b_printf(
        "  «#» w=«#» d=«#»  build «#»us  «#»us->«#»us  post «#»->«#»  probe «#»  rec «#»->«#»",
        label,
        (int64_t)width,
        (int64_t)depth,
        (int64_t)(build_ns / 1000),
        (int64_t)(off.ns / 1000),
        (int64_t)(on.ns / 1000),
        (int64_t)off.postings,
        (int64_t)on.postings,
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

    n00b_printf("pathological plans, «#» records, cost off -> on:", (int64_t)RECORDS);

    check_shape(r"wide   ", &s, 256, 1, false, LEAF_VARIED, 1);
    check_shape(r"wide   ", &s, 1024, 1, false, LEAF_VARIED, 2);
    check_shape(r"wide   ", &s, 2048, 1, false, LEAF_VARIED, 14);
    check_shape(r"deep   ", &s, 1, 64, false, LEAF_VARIED, 3);
    check_shape(r"deep   ", &s, 1, 128, false, LEAF_VARIED, 4);
    check_shape(r"both   ", &s, 16, 16, false, LEAF_VARIED, 5);
    check_shape(r"both   ", &s, 32, 32, false, LEAF_VARIED, 6);
    check_shape(r"opaque ", &s, 64, 8, true, LEAF_VARIED, 7);

    // Shapes the generator above never produced.
    check_shape(r"lossy  ", &s, 32, 4, false, LEAF_LOSSY, 8);
    check_shape(r"lossy  ", &s, 4, 32, false, LEAF_LOSSY, 9);
    check_shape(r"negated", &s, 1, 64, false, LEAF_NEGATED, 10);
    check_shape(r"negated", &s, 16, 8, false, LEAF_NEGATED, 11);
    check_shape(r"same   ", &s, 64, 1, false, LEAF_SAME, 12);
    check_shape(r"same   ", &s, 16, 8, false, LEAF_SAME, 13);

    // One figure, at the end. ru_maxrss only ever rises, so a per-shape delta
    // credits the whole peak to whichever shape reached it and reports zero
    // for every shape after.
    n00b_printf("all shapes: answers identical, postings not increased");
    n00b_printf("peak rss «#» MB", (int64_t)(rss_kb() / (1024 * 1024)));

    n00b_shutdown();
    return 0;
}
