/*
 * A/B benchmark: same source compiled against the branch and against the
 * merge base. Uses only APIs that exist in both, so the only variable is the
 * rocs implementation linked in.
 *
 * Reports ingest, plan build, and execution separately, because the branch
 * touches all three and the ordering win is only one of them.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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
        n00b_require((expr), "bench check failed: " #expr);                                    \
    } while (0)

static n00b_allocator_t *
bench_shard_allocator(void)
{
    static n00b_pool_t       pool;
    static n00b_allocator_t *shared = nullptr;

    if (shared == nullptr) {
        shared = n00b_pool_init(&pool,
                                .hidden            = true,
                                .external_metadata = false,
                                .inline_headers    = true,
                                .name              = "rocs_bench_shard_pool");
    }
    return shared;
}

#define RECORDS_DEFAULT UINT64_C(4096)

// Shard size, and how many times each measurement repeats. Registered as a
// test, this runs small and once: what CI checks is that every shape still
// answers the same with costing on and off, which needs neither a big shard
// nor a stable clock. Run it by hand with no environment set for the timings.
static uint64_t records = RECORDS_DEFAULT;
static int      repeats = 5;

static uint64_t
env_u64(const char *name, uint64_t fallback)
{
    const char *v = getenv(name);
    if (v == nullptr || *v == '\0') {
        return fallback;
    }
    return (uint64_t)strtoull(v, nullptr, 10);
}

#define RECORDS records

// Field g<m> holds i % m, so residue 0 of a larger modulus implies residue 0 of
// every smaller one and a conjunction across the whole ladder matches
// RECORDS/TAG_MOD_MAX records. The leaves it is built from span a 128x spread
// in document frequency, which is the spread an intersection order can exploit.
#define TAG_MOD_MIN UINT64_C(2)
#define TAG_LADDER  8

static uint64_t
tag_mod(uint64_t rung)
{
    return TAG_MOD_MIN << (rung % TAG_LADDER);
}

static n00b_string_t *
tag_field(uint64_t rung)
{
    return n00b_cformat("g«#»", (int64_t)tag_mod(rung));
}

typedef struct {
    n00b_store_shard_t     *shard;
    // The same records sealed. Every shape runs against both, because the two
    // residencies price the same work differently, since a sealed image is a
    // contiguous array to walk and a scattered one to search, and the cost
    // model carries separate coefficients for them that nothing else derives.
    n00b_store_map_t       *map;
    n00b_store_map_shard_t *sealed;
    n00b_store_index_t     *level;
    n00b_store_index_t     *trace;
    n00b_store_index_t     *band;
    n00b_store_index_t     *msg;
    // One field per rung, because a conjunction over two values of the SAME
    // field is empty for every record: a record has one band, so band-3 AND
    // band-9 matches nothing and leaves the intersection order with nothing to
    // choose between. Across distinct fields it is satisfiable.
    n00b_store_index_t     *ladder[TAG_LADDER];
} sample_t;

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

// Ingest, timed. This is the path rocs_posting_list_push sits on.
static sample_t
sample(uint64_t *ingest_ns)
{
    auto shard_r = n00b_store_shard_new(.shard_id  = UINT64_C(0x9A7),
                                        .allocator = bench_shard_allocator());
    CHECK(n00b_result_is_ok(shard_r));

    sample_t s = {
        .shard = n00b_result_get(shard_r),
        .level = index_of(r"level", N00B_STORE_INDEX_TERM),
        .trace = index_of(r"trace", N00B_STORE_INDEX_TERM),
        .band  = index_of(r"band", N00B_STORE_INDEX_TERM),
        .msg   = ngram_of(r"msg"),
    };
    for (uint64_t g = 0; g < TAG_LADDER; g++) {
        s.ladder[g] = index_of(tag_field(g), N00B_STORE_INDEX_TERM);
    }

    uint64_t start = now_ns();
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
        n00b_json_object_put_n00b(
            rec,
            r"band",
            n00b_json_string_new_from_n00b(n00b_cformat("band-«#»", (int64_t)(i % 16))));
        for (uint64_t g = 0; g < TAG_LADDER; g++) {
            n00b_json_object_put_n00b(
                rec,
                tag_field(g),
                n00b_json_string_new_from_n00b(
                    n00b_cformat("v«#»", (int64_t)(i % tag_mod(g)))));
        }
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
        for (uint64_t g = 0; g < TAG_LADDER; g++) {
            CHECK(n00b_result_is_ok(
                n00b_store_index_add(s.ladder[g], s.shard, ord)));
        }
    }
    *ingest_ns = now_ns() - start;
    return s;
}

typedef enum {
    LEAF_VARIED = 0,
    LEAF_LOSSY,
    LEAF_NEGATED,
    LEAF_SAME,
    LEAF_GRADED,
} leaf_kind_t;

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

// Walks the ladder rather than sampling it, so a group of width w holds every
// rung it can reach and the cheapest leaf is always present to be found.
static uint64_t graded_rung = 0;

static n00b_plan_predicate_t *
graded_leaf(void)
{
    return eq(tag_field(graded_rung++), r"v0");
}

static n00b_plan_predicate_t *
lossy_leaf(void)
{
    auto r
        = n00b_plan_predicate_prefix(target(r"msg"), n00b_cformat("m«#»-", (int64_t)rng(64)));
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
negated_leaf(void)
{
    auto r = n00b_plan_predicate_not(varied_leaf());
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
opaque_leaf(void)
{
    auto r = n00b_plan_predicate_exists(target(r"trace"));
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
leaf_of(leaf_kind_t kind)
{
    switch (kind) {
    case LEAF_LOSSY:
        return lossy_leaf();
    case LEAF_NEGATED:
        return negated_leaf();
    case LEAF_SAME:
        return eq(r"level", r"info");
    case LEAF_GRADED:
        return graded_leaf();
    default:
        return varied_leaf();
    }
}

static n00b_plan_predicate_t *
group_of(n00b_plan_predicate_list_t *kids, bool conjunction)
{
    auto r = conjunction ? n00b_plan_predicate_and(kids) : n00b_plan_predicate_or(kids);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
build(uint64_t width, uint64_t depth, bool conjunction, bool opaque, leaf_kind_t kind)
{
    n00b_plan_predicate_list_t *kids = n00b_plan_predicate_list_new();
    CHECK(kids != nullptr);

    for (uint64_t i = 0; i < width; i++) {
        CHECK(n00b_result_is_ok(
            n00b_plan_predicate_list_append(kids,
                                            opaque && i == 0 ? opaque_leaf() : leaf_of(kind))));
    }
    if (depth > 1) {
        CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(
            kids,
            build(width, depth - 1, !conjunction, opaque, kind))));
    }
    if (width == 1 && depth == 1) {
        return leaf_of(kind);
    }
    return group_of(kids, conjunction);
}

static n00b_plan_node_t *
plan_of(sample_t *s, n00b_plan_predicate_t *pred, bool mapped)
{
    n00b_plan_index_list_t *ix = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->level)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->trace)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->band)));
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(ix, s->msg)));
    for (uint64_t g = 0; g < TAG_LADDER; g++) {
        CHECK(n00b_result_is_ok(
            n00b_plan_index_list_append(ix, s->ladder[g])));
    }
    auto r = n00b_plan_build(pred, ix);
    CHECK(n00b_result_is_ok(r));
    n00b_plan_node_t *plan = n00b_result_get(r);

    if (mapped) {
        CHECK(n00b_result_is_ok(n00b_plan_collect_mapped(plan, s->sealed)));
        auto rc = _rocs_plan_mapped_record_count(s->sealed);
        (void)n00b_plan_settle(plan,
                               n00b_result_is_ok(rc) ? n00b_result_get(rc) : 0);
    }
    else {
        CHECK(n00b_result_is_ok(n00b_plan_collect_hot(plan, s->shard)));
        (void)n00b_plan_settle(plan, s->shard->record_count);
    }
    return plan;
}

#define REPEATS repeats

// Answer fingerprint, so the two builds can be compared for agreement and not
// merely for speed.
static uint64_t
fingerprint(n00b_plan_ordset_t *set)
{
    uint64_t h = UINT64_C(1469598103934665603);
    for (uint64_t i = 0; i < RECORDS; i++) {
        auto c = n00b_plan_ordset_contains(set, i);
        CHECK(n00b_result_is_ok(c));
        h ^= n00b_result_get(c) ? (i + 1) : 0;
        h *= UINT64_C(1099511628211);
    }
    return h;
}

// Shapes share one fixture, so whatever a shape leaves behind (warm posting
// caches, a grown allocator) is state the next one inherits. That makes a row's
// timing depend on the rows before it, which is not a property of the shape.
// ROCS_BENCH_ONLY=<n> runs the nth shape alone, so a harness can give every
// shape its own process and compare rows that were measured the same way.
static uint64_t shape_ordinal = 0;

static bool
shape_selected(void)
{
    const char *want = getenv("ROCS_BENCH_ONLY");
    uint64_t    mine = shape_ordinal++;

    if (want == nullptr) {
        return true;
    }
    return (uint64_t)strtoull(want, nullptr, 10) == mine;
}

// One exec, either residency. The A/B assertion below has to run in both,
// because ordering and the empty short circuit are decided from counts and the
// two residencies supply them from different structures.
static n00b_result_t(n00b_plan_ordset_t *)
exec_either(n00b_plan_node_t *plan, sample_t *s, bool mapped)
{
    if (mapped) {
        return n00b_plan_exec_mapped(plan, s->sealed);
    }
    return n00b_plan_exec_hot(plan, s->shard);
}

static void
shape(n00b_string_t *label,
      sample_t      *s,
      uint64_t       width,
      uint64_t       depth,
      bool           opaque,
      leaf_kind_t    kind,
      uint64_t       seed,
      bool           mapped)
{
    if (!shape_selected()) {
        return;
    }

    rng_state                   = seed;
    n00b_plan_predicate_t *pred = build(width, depth, true, opaque, kind);

    // One build discarded. The first touches pages and warms the index's
    // posting caches, which is a cost the shape pays once and not per plan.
    (void)plan_of(s, pred, mapped);

    uint64_t bstart = now_ns();
    for (int i = 0; i < REPEATS; i++) {
        (void)plan_of(s, pred, mapped);
    }
    uint64_t build_ns = (now_ns() - bstart) / REPEATS;

    n00b_plan_node_t *plan = plan_of(s, pred, mapped);

    auto warm_r = exec_either(plan, s, mapped);
    CHECK(n00b_result_is_ok(warm_r));

    uint64_t best                             = UINT64_MAX;
    n00b_result_t(n00b_plan_ordset_t *) set_r = warm_r;
    for (int round = 0; round < 3; round++) {
        uint64_t start = now_ns();
        for (int i = 0; i < REPEATS; i++) {
            set_r = exec_either(plan, s, mapped);
            CHECK(n00b_result_is_ok(set_r));
        }
        uint64_t ns = (now_ns() - start) / REPEATS;
        if (ns < best) {
            best = ns;
        }
    }

    auto count_r = n00b_plan_ordset_count(n00b_result_get(set_r));
    CHECK(n00b_result_is_ok(count_r));

    // Index probes are deterministic where wall clock is not, so they say
    // whether a different intersection order was chosen without the machine
    // getting a vote. One execution each, outside the timing loop.
    // Deterministic, so a debug build reports them and a release build reports
    // zero without either number losing meaning: the count does not depend on
    // optimization, and wall clock, which does, is only trustworthy in release.
    uint64_t costed_probes = 0;
#ifdef N00B_DEBUG
    n00b_plan_index_probes_reset();
    n00b_plan_postings_walked_reset();
    auto probe_r = exec_either(plan, s, mapped);
    CHECK(n00b_result_is_ok(probe_r));
    costed_probes = n00b_plan_index_probes() + n00b_plan_postings_walked();
#endif

    // The claim the whole cost model rests on: ordering and the plan-time
    // short circuits change how much work a query does, never what it answers.
    // Checked per shape rather than reported, so a build that broke it fails
    // here instead of printing two columns nobody diffs.
    //
    // The second plan is built as well as run with costing off, because two of
    // the three plan-time decisions happen while the plan is built. Reusing
    // the first plan would compare execution alone and pass on a planner that
    // had already thrown the answer away.
    uint64_t costed_fp = fingerprint(n00b_result_get(set_r));
    uint64_t costed_n  = n00b_result_get(count_r);

    bool was_enabled = n00b_plan_cost_enabled();
    n00b_plan_cost_set_enabled(false);

    n00b_plan_node_t *plain     = plan_of(s, pred, mapped);
    auto              plain_r   = exec_either(plain, s, mapped);
    CHECK(n00b_result_is_ok(plain_r));
    auto plain_count_r = n00b_plan_ordset_count(n00b_result_get(plain_r));
    CHECK(n00b_result_is_ok(plain_count_r));

    uint64_t plain_probes = 0;
#ifdef N00B_DEBUG
    n00b_plan_index_probes_reset();
    n00b_plan_postings_walked_reset();
    auto plain_probe_r = exec_either(plain, s, mapped);
    CHECK(n00b_result_is_ok(plain_probe_r));
    plain_probes = n00b_plan_index_probes() + n00b_plan_postings_walked();
#endif

    CHECK(n00b_result_get(plain_count_r) == costed_n);
    CHECK(fingerprint(n00b_result_get(plain_r)) == costed_fp);

    n00b_plan_cost_set_enabled(was_enabled);

    n00b_printf("  [«#»] «#» «#» w=«#» d=«#»  build «#»us  exec «#»us  "
                "probes «#»/«#»  n=«#» fp=«#»",
                (int64_t)(shape_ordinal - 1),
                mapped ? r"sealed" : r"hot   ",
                label,
                (int64_t)width,
                (int64_t)depth,
                (int64_t)(build_ns / 1000),
                (int64_t)(best / 1000),
                (int64_t)costed_probes,
                (int64_t)plain_probes,
                (int64_t)n00b_result_get(count_r),
                (int64_t)(costed_fp & 0xffffffff));
}

// ROCS_BENCH_RESIDENCY=hot|sealed runs one arm alone. Both by default. Useful
// for isolating a failure to a residency, and for confirming that the sealed
// arm asserts on its own rather than only ever being reached after the hot arm
// has already passed.
static bool
residency_selected(bool mapped)
{
    const char *want = getenv("ROCS_BENCH_RESIDENCY");

    if (want == nullptr) {
        return true;
    }
    return strcmp(want, mapped ? "sealed" : "hot") == 0;
}

static void
run_all_shapes(sample_t *s, bool mapped)
{
    if (!residency_selected(mapped)) {
        return;
    }
    shape_ordinal = 0;
    shape(r"wide   ", s, 256, 1, false, LEAF_VARIED, 1, mapped);
    shape(r"wide   ", s, 1024, 1, false, LEAF_VARIED, 2, mapped);
    shape(r"deep   ", s, 1, 64, false, LEAF_VARIED, 3, mapped);
    shape(r"deep   ", s, 1, 128, false, LEAF_VARIED, 4, mapped);
    shape(r"both   ", s, 16, 16, false, LEAF_VARIED, 5, mapped);
    shape(r"both   ", s, 32, 32, false, LEAF_VARIED, 6, mapped);
    shape(r"opaque ", s, 64, 8, true, LEAF_VARIED, 7, mapped);
    shape(r"lossy  ", s, 32, 4, false, LEAF_LOSSY, 8, mapped);
    shape(r"lossy  ", s, 4, 32, false, LEAF_LOSSY, 9, mapped);
    shape(r"negated", s, 1, 64, false, LEAF_NEGATED, 10, mapped);
    shape(r"negated", s, 16, 8, false, LEAF_NEGATED, 11, mapped);
    shape(r"same   ", s, 64, 1, false, LEAF_SAME, 12, mapped);
    shape(r"same   ", s, 16, 8, false, LEAF_SAME, 13, mapped);
    shape(r"narrow ", s, 2, 1, false, LEAF_VARIED, 14, mapped);
    shape(r"graded ", s, 8, 1, false, LEAF_GRADED, 15, mapped);
    shape(r"graded ", s, 64, 1, false, LEAF_GRADED, 16, mapped);
    shape(r"graded ", s, 16, 8, false, LEAF_GRADED, 17, mapped);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    records = env_u64("ROCS_BENCH_RECORDS", RECORDS_DEFAULT);
    repeats = (int)env_u64("ROCS_BENCH_REPEATS", 5);
    CHECK(records >= 64 && repeats >= 1);

    // Times the arm the caller asks for. The correctness check inside each
    // shape runs the other arm regardless, so the fingerprints still have to
    // agree whichever way this is set.
    n00b_plan_cost_set_enabled(env_u64("ROCS_BENCH_COST", 1) != 0);

    uint64_t ingest_ns = 0;
    sample_t s         = sample(&ingest_ns);

    n00b_printf("rocs A/B bench, «#» records", (int64_t)RECORDS);
    n00b_printf("  ingest «#»us", (int64_t)(ingest_ns / 1000));

    run_all_shapes(&s, false);

    // The same records, sealed, and every shape again. Unions, complements and
    // lossy leaves were only ever A/B'd hot; the sealed path is the one all
    // three production callers use, and it is where a plan settled from the
    // wrong counts actually costs something.
    auto seal_r = n00b_store_shard_seal(s.shard,
                                        .seal_ts      = 4242,
                                        .base_address = 0xB00000u);
    CHECK(n00b_result_is_ok(seal_r));
    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    s.map       = n00b_result_get(map_r);
    auto root_r = n00b_store_map_root(s.map);
    CHECK(n00b_result_is_ok(root_r));
    s.sealed = n00b_result_get(root_r);

    run_all_shapes(&s, true);

    CHECK(n00b_result_is_ok(n00b_store_map_close(s.map)));

    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    n00b_printf("peak rss «#» MB", (int64_t)((uint64_t)ru.ru_maxrss >> 20));

    n00b_shutdown();
    return 0;
}
