/* test/unit/test_rocs_zone_map.c - per-shard value bounds and range pruning.
 *
 * The motivating case is stated in plan.c: under ingest-clock time
 * partitioning the shard's route key reflects arrival, not event time, so it
 * cannot constrain an event-time predicate and every shard in the store gets
 * opened. Each open costs a residency pin, a map root and a catalog
 * validation before any useful work begins.
 *
 * So the assertions here are about how many shards survive the filter, not
 * about which records come back. Answers are checked too, because a prune that
 * loses a record is the one failure mode that matters, but a test that only
 * checked answers would pass with the pruning deleted.
 */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>

#include "internal/rocs/plan_ir.h"
#include "internal/rocs/eval.h"
#include "internal/rocs/store.h"
#include "rocs_test_support.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                     \
    } while (0)

static n00b_vfs_t *
new_memory_vfs(void)
{
    auto vfs_r = n00b_vfs_new();
    CHECK(n00b_result_is_ok(vfs_r));
    n00b_vfs_t *vfs = n00b_result_get(vfs_r);

    auto be_r = n00b_vfs_backend_memory_new();
    CHECK(n00b_result_is_ok(be_r));

    auto mount_r = n00b_vfs_mount(vfs, r"/", n00b_result_get(be_r), 0);
    CHECK(n00b_result_is_ok(mount_r));
    return vfs;
}

static n00b_store_t *
open_store(n00b_vfs_t *vfs)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_schema_t *schema = n00b_result_get(schema_r);

    // Declared but unindexed. A range has no index path at all (plan.h), so
    // this is exactly the shape the zone map is for: without it the only way
    // to answer is to read every record of every shard.
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"ts")));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"host")));

    auto store_r = n00b_store_open_vfs(vfs, r"/rocs", schema);
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_json_node_t *
record_ts(int64_t id, int64_t ts)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    n00b_json_object_put_n00b(record, r"ts", n00b_json_int_new(ts));
    return record;
}

static n00b_json_node_t *
record_ts_double(int64_t id, double ts)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    n00b_json_object_put_n00b(record, r"ts", n00b_json_double_new(ts));
    return record;
}

static n00b_json_node_t *
record_host(int64_t id, n00b_string_t *host)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    n00b_json_object_put_n00b(record,
                              r"host",
                              n00b_json_string_new_from_n00b(host));
    return record;
}

static void
ingest(n00b_store_t *store, n00b_json_node_t *record)
{
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, record)));
}

static void
seal(n00b_store_t *store, uint64_t seal_ts)
{
    CHECK(n00b_result_is_ok(n00b_store_seal_hot_shard(store,
                                                      .seal_ts = seal_ts)));
}

// One shard per decade of ts: [0,9], [100,109], [200,209], [300,309].
static void
build_four_shards(n00b_store_t *store)
{
    for (int64_t shard = 0; shard < 4; shard++) {
        for (int64_t i = 0; i < 10; i++) {
            ingest(store, record_ts(shard * 100 + i, shard * 100 + i));
        }
        seal(store, 1000 + (uint64_t)shard);
    }
}

static n00b_plan_target_t *
field_target(n00b_string_t *field)
{
    auto r = n00b_plan_target_field(field);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
predicate_range(n00b_string_t *f, int64_t lower, int64_t upper)
{
    auto r = n00b_plan_predicate_range(
        field_target(f),
        json_value(n00b_json_int_new(lower)),
        json_value(n00b_json_int_new(upper)));
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
predicate_eq_int(n00b_string_t *f, int64_t value)
{
    auto r = n00b_plan_predicate_eq(field_target(f),
                                    json_value(n00b_json_int_new(value)));
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
predicate_eq_str(n00b_string_t *f, n00b_string_t *value)
{
    auto r = n00b_plan_predicate_eq(
        field_target(f),
        json_value(n00b_json_string_new_from_n00b(value)));
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
predicate_exists(n00b_string_t *f)
{
    auto r = n00b_plan_predicate_exists(field_target(f));
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

// A range with its bounds spelled out. The helper above takes the closed
// defaults, which never reach the inclusivity arms of the overlap test.
static n00b_plan_predicate_t *
predicate_range_x(n00b_string_t *f,
                  int64_t        lower,
                  bool           include_lower,
                  int64_t        upper,
                  bool           include_upper)
{
    auto r = n00b_plan_predicate_range(
        field_target(f),
        json_value(n00b_json_int_new(lower)),
        json_value(n00b_json_int_new(upper)),
        .include_lower = include_lower,
        .include_upper = include_upper);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
predicate_in_ints(n00b_string_t *f, const int64_t *values, size_t count)
{
    n00b_plan_value_list_t *list = n00b_plan_value_list_new();
    for (size_t i = 0; i < count; i++) {
        CHECK(n00b_result_is_ok(n00b_plan_value_list_append(
            list,
            json_value(n00b_json_int_new(values[i])))));
    }
    auto r = n00b_plan_predicate_in(field_target(f), list);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
predicate_group(bool                    conjunction,
                n00b_plan_predicate_t  *a,
                n00b_plan_predicate_t  *b)
{
    n00b_plan_predicate_list_t *kids = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(kids, a)));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(kids, b)));
    auto r = conjunction ? n00b_plan_predicate_and(kids)
                         : n00b_plan_predicate_or(kids);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_plan_predicate_t *
predicate_not(n00b_plan_predicate_t *child)
{
    auto r = n00b_plan_predicate_not(child);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

// Shards the filter kept, and the records they matched between them.
static uint64_t
shards_read(n00b_store_t *store, n00b_plan_predicate_t *predicate,
            uint64_t *records_out)
{
    n00b_plan_index_list_t *indexes = n00b_plan_index_list_new();
    auto results_r = n00b_plan_store_sealed(store, predicate, indexes);
    CHECK(n00b_result_is_ok(results_r));
    n00b_plan_shard_result_list_t *results = n00b_result_get(results_r);

    auto count_r = n00b_plan_shard_result_count(results);
    CHECK(n00b_result_is_ok(count_r));
    uint64_t shards = n00b_result_get(count_r);

    uint64_t records = 0;
    for (uint64_t i = 0; i < shards; i++) {
        auto at_r = n00b_plan_shard_result_at(results, i);
        CHECK(n00b_result_is_ok(at_r));
        auto opt = n00b_result_get(at_r);
        CHECK(n00b_option_is_set(opt));

        // Matched ordinals, not the shard's record count: the latter is the
        // universe the result was computed against, which is the same whether
        // one record matched or none did.
        auto ords_r = n00b_plan_shard_result_ordinals(n00b_option_get(opt));
        CHECK(n00b_result_is_ok(ords_r));
        auto n_r = n00b_plan_ordset_count(n00b_result_get(ords_r));
        CHECK(n00b_result_is_ok(n_r));
        records += n00b_result_get(n_r);
    }

    if (records_out != nullptr) {
        *records_out = records;
    }
    return shards;
}

// ---------------------------------------------------------------------------

static void
test_range_skips_shards(void)
{
    n00b_store_t *store = open_store(new_memory_vfs());
    build_four_shards(store);

    // A range inside one decade reaches one shard. Before zone maps every
    // range predicate reached all four, because routing leaves a range
    // unconstrained and a range has no index to narrow it.
    uint64_t records = 0;
    CHECK(shards_read(store, predicate_range(r"ts", 102, 105), &records) == 1);
    CHECK(records == 4);

    // Spanning two decades reaches two: 105..109 in one, 200..205 in the
    // other.
    CHECK(shards_read(store, predicate_range(r"ts", 105, 205), &records) == 2);
    CHECK(records == 11);

    // A range below everything reaches none at all, so the query opens no
    // shard and reads no record.
    CHECK(shards_read(store, predicate_range(r"ts", 900, 999), &records) == 0);
    CHECK(records == 0);

    // A range covering everything still reaches all four. Pruning must not
    // lose a shard whose values it does cover.
    CHECK(shards_read(store, predicate_range(r"ts", 0, 1000), &records) == 4);
    CHECK(records == 40);

    // A gap between two shards' recorded intervals: nothing holds 10..99.
    CHECK(shards_read(store, predicate_range(r"ts", 10, 99), &records) == 0);
    CHECK(records == 0);
}

static void
test_bound_edges_are_respected(void)
{
    n00b_store_t *store = open_store(new_memory_vfs());
    build_four_shards(store);

    uint64_t records = 0;

    // Touching a shard's greatest value exactly still reaches it.
    CHECK(shards_read(store, predicate_range(r"ts", 9, 9), &records) == 1);
    CHECK(records == 1);

    // One past it reaches nothing.
    CHECK(shards_read(store, predicate_range(r"ts", 10, 10), &records) == 0);
    CHECK(records == 0);

    // Touching a shard's least value exactly still reaches it.
    CHECK(shards_read(store, predicate_range(r"ts", 300, 300), &records) == 1);
    CHECK(records == 1);
}

// An open bound is what decides the touching case, where the asked-for
// interval and the shard's own meet at exactly one value. Closed everywhere
// else here, so without these the inclusivity arms never run.
static void
test_exclusive_bounds_decide_the_touching_case(void)
{
    n00b_store_t *store = open_store(new_memory_vfs());
    build_four_shards(store);

    uint64_t records = 0;

    // The first shard holds [0, 9]. A range opening just above its greatest
    // value shares nothing with it, and neither does one closing just below
    // the next shard's least.
    CHECK(shards_read(store,
                      predicate_range_x(r"ts", 9, false, 99, true),
                      &records)
          == 0);
    CHECK(records == 0);

    // The same bounds closed reach it, on that one value.
    CHECK(shards_read(store,
                      predicate_range_x(r"ts", 9, true, 99, true),
                      &records)
          == 1);
    CHECK(records == 1);

    // Mirrored at the top: a range closing on a shard's least value reaches
    // it, and one closing just short of it does not.
    CHECK(shards_read(store,
                      predicate_range_x(r"ts", 50, true, 100, true),
                      &records)
          == 1);
    CHECK(records == 1);
    CHECK(shards_read(store,
                      predicate_range_x(r"ts", 50, true, 100, false),
                      &records)
          == 0);
    CHECK(records == 0);
}

// The walk over a predicate, rather than the single leaf every other case
// here passes. Each connective skips on a different rule, and NOT skips on
// none at all.
static void
test_composite_predicates_prune(void)
{
    n00b_store_t *store = open_store(new_memory_vfs());
    build_four_shards(store);

    uint64_t records = 0;

    // One impossible conjunct ends it: nothing in [900, 999] exists, so no
    // shard need be opened however reachable the other conjunct is.
    CHECK(shards_read(store,
                      predicate_group(true,
                                      predicate_range(r"ts", 102, 105),
                                      predicate_range(r"ts", 900, 999)),
                      &records)
          == 0);
    CHECK(records == 0);

    // A disjunction needs every branch impossible before it is. One
    // unreachable branch beside one reachable one reaches the reachable
    // shard and nothing else.
    CHECK(shards_read(store,
                      predicate_group(false,
                                      predicate_range(r"ts", 900, 999),
                                      predicate_range(r"ts", 102, 105)),
                      &records)
          == 1);
    CHECK(records == 4);

    // Both branches unreachable prunes everything.
    CHECK(shards_read(store,
                      predicate_group(false,
                                      predicate_range(r"ts", 900, 999),
                                      predicate_range(r"ts", 1000, 1009)),
                      &records)
          == 0);
    CHECK(records == 0);

    // A negation may never prune. A shard holding no value in [102, 105] is
    // exactly a shard where the negation holds for every record, so bounds
    // that rule the child out say nothing about the parent.
    CHECK(shards_read(store,
                      predicate_not(predicate_range(r"ts", 102, 105)),
                      &records)
          == 4);
    CHECK(records == 36);

    // An IN keeps the shard on one candidate inside the interval.
    int64_t hit[]  = {5000, 204};
    int64_t miss[] = {5000, 6000};
    CHECK(shards_read(store, predicate_in_ints(r"ts", hit, 2), &records) == 1);
    CHECK(records == 1);
    CHECK(shards_read(store, predicate_in_ints(r"ts", miss, 2), &records) == 0);
    CHECK(records == 0);
}

// n00b_plan_store_sealed rewrites before it builds the partition filter, so
// the filter reads the folded tree. This is the one path where a rewrite bug
// would cost an answer rather than time, and it is what the hoist above
// n00b_plan_partition_filter is for.
static void
test_rewritten_predicates_reach_the_filter(void)
{
    n00b_store_t *store = open_store(new_memory_vfs());
    build_four_shards(store);

    uint64_t records = 0;

    // Two disjoint ranges on one field fold to FALSE, which prunes every
    // shard. Only the rewritten tree knows it folded: as written, these are
    // two reachable conjuncts and the filter would keep the shard each one
    // reaches.
    CHECK(shards_read(store,
                      predicate_group(true,
                                      predicate_range(r"ts", 1, 2),
                                      predicate_range(r"ts", 8, 9)),
                      &records)
          == 0);
    CHECK(records == 0);

    // A leaf beside its own negation folds to TRUE, which reaches every
    // shard and keeps every record.
    CHECK(shards_read(store,
                      predicate_group(false,
                                      predicate_eq_int(r"ts", 5),
                                      predicate_not(predicate_eq_int(r"ts", 5))),
                      &records)
          == 4);
    CHECK(records == 40);

    // Merging two overlapping ranges narrows what the filter is asked about:
    // [102, 105] and [104, 108] intersect to [104, 105], which is one shard
    // either way, but the fold has to preserve the records.
    CHECK(shards_read(store,
                      predicate_group(true,
                                      predicate_range(r"ts", 102, 105),
                                      predicate_range(r"ts", 104, 108)),
                      &records)
          == 1);
    CHECK(records == 2);
}

static void
test_equality_prunes_too(void)
{
    n00b_store_t *store = open_store(new_memory_vfs());
    build_four_shards(store);

    uint64_t records = 0;
    CHECK(shards_read(store, predicate_eq_int(r"ts", 204), &records) == 1);
    CHECK(records == 1);

    CHECK(shards_read(store, predicate_eq_int(r"ts", 5000), &records) == 0);
    CHECK(records == 0);
}

static void
test_unprunable_predicates_read_everything(void)
{
    n00b_store_t *store = open_store(new_memory_vfs());
    build_four_shards(store);

    uint64_t records = 0;

    // A bound says nothing about existence: every shard has the field.
    CHECK(shards_read(store, predicate_exists(r"ts"), &records) == 4);
    CHECK(records == 40);

    // A field no record carried has no bounds, so nothing may be skipped on
    // its account.
    CHECK(shards_read(store, predicate_eq_str(r"host", r"web1"), &records)
          == 4);
    CHECK(records == 0);
}

static void
test_mixed_types_disable_the_field(void)
{
    n00b_store_t *store = open_store(new_memory_vfs());

    // A shard whose `ts` is sometimes a string has no interval: a string and
    // a number have no order between them, so no [min, max] describes both.
    ingest(store, record_ts(1, 5));
    n00b_json_node_t *odd = n00b_json_object_new();
    n00b_json_object_put_n00b(odd, r"id", n00b_json_int_new(2));
    n00b_json_object_put_n00b(odd,
                              r"ts",
                              n00b_json_string_new_from_n00b(r"yesterday"));
    ingest(store, odd);
    seal(store, 1000);

    // A second shard with ordinary values, which stays prunable.
    ingest(store, record_ts(3, 500));
    seal(store, 1001);

    // The mixed shard cannot be ruled out; the clean one can.
    uint64_t records = 0;
    CHECK(shards_read(store, predicate_range(r"ts", 900, 999), &records) == 1);
    CHECK(records == 0);
}

static void
test_bounds_survive_a_reopen(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs();
    n00b_store_t *store = open_store(vfs);
    build_four_shards(store);

    uint64_t before = 0;
    CHECK(shards_read(store, predicate_range(r"ts", 102, 105), &before) == 1);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));

    // The bounds are catalog metadata, not shard payload, so this is what
    // proves they were written and read back. Kept in memory only, pruning
    // would silently stop after any restart -- correct answers, every shard
    // opened, and nothing failing to say so.
    n00b_store_t *reopened = open_store(vfs);

    uint64_t after = 0;
    CHECK(shards_read(reopened, predicate_range(r"ts", 102, 105), &after) == 1);
    CHECK(after == before);

    CHECK(shards_read(reopened, predicate_range(r"ts", 900, 999), &after) == 0);
    CHECK(shards_read(reopened, predicate_range(r"ts", 0, 1000), &after) == 4);
    CHECK(after == 40);
}

static void
test_string_bounds(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs();
    n00b_store_t *store = open_store(vfs);

    ingest(store, record_host(1, r"alpha"));
    ingest(store, record_host(2, r"beta"));
    seal(store, 1000);

    ingest(store, record_host(3, r"yankee"));
    ingest(store, record_host(4, r"zulu"));
    seal(store, 1001);

    uint64_t records = 0;
    CHECK(shards_read(store, predicate_eq_str(r"host", r"beta"), &records)
          == 1);
    CHECK(records == 1);

    CHECK(shards_read(store, predicate_eq_str(r"host", r"zulu"), &records)
          == 1);
    CHECK(records == 1);

    // Ordered between the two shards' intervals, so neither can hold it.
    CHECK(shards_read(store, predicate_eq_str(r"host", r"mike"), &records)
          == 0);
    CHECK(records == 0);

    // And the bounds round-trip as strings, not as numbers.
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
    n00b_store_t *reopened = open_store(vfs);
    CHECK(shards_read(reopened, predicate_eq_str(r"host", r"mike"), &records)
          == 0);
    CHECK(shards_read(reopened, predicate_eq_str(r"host", r"alpha"), &records)
          == 1);
}

// Doubles, which no other case here writes, so without this the double arm of
// the bound codec is never encoded, never decoded, and the bit pattern it
// round-trips through is never checked against anything.
static void
test_double_bounds(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs();
    n00b_store_t *store = open_store(vfs);

    // A value no decimal string round-trips exactly, so a bound written as
    // text would come back a rounding step off and the comparisons below
    // would land on the wrong side of it.
    ingest(store, record_ts_double(1, 0.1));
    ingest(store, record_ts_double(2, 2.5));
    seal(store, 1000);

    ingest(store, record_ts_double(3, 100.25));
    ingest(store, record_ts_double(4, 109.75));
    seal(store, 1001);

    uint64_t records = 0;
    CHECK(shards_read(store, predicate_range(r"ts", 0, 3), &records) == 1);
    CHECK(records == 2);

    // Ordering crosses the two numeric types, which is what lets an integer
    // range constrain a shard whose bounds are doubles.
    CHECK(shards_read(store, predicate_range(r"ts", 3, 99), &records) == 0);
    CHECK(records == 0);

    CHECK(shards_read(store, predicate_range(r"ts", 100, 110), &records) == 1);
    CHECK(records == 2);

    // Through the catalog, where the bound is eight bytes of IEEE rather
    // than a number the writer had to render.
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
    n00b_store_t *reopened = open_store(vfs);

    CHECK(shards_read(reopened, predicate_range(r"ts", 3, 99), &records) == 0);
    CHECK(shards_read(reopened, predicate_range(r"ts", 0, 3), &records) == 1);
    CHECK(records == 2);

    // The exact least value, which only survives if the bits did.
    auto exact_r = n00b_plan_predicate_eq(
        field_target(r"ts"),
        json_value(n00b_json_double_new(0.1)));
    CHECK(n00b_result_is_ok(exact_r));
    CHECK(shards_read(reopened, n00b_result_get(exact_r), &records) == 1);
    CHECK(records == 1);

    // And just under it, which must not.
    auto under_r = n00b_plan_predicate_eq(
        field_target(r"ts"),
        json_value(n00b_json_double_new(0.0999)));
    CHECK(n00b_result_is_ok(under_r));
    CHECK(shards_read(reopened, n00b_result_get(under_r), &records) == 0);
    CHECK(records == 0);
}

// The control arm. Turning maintenance off has to stop bounds being recorded,
// or a run that means to measure the no-zone-map case measures the zone-map
// case twice and reports that the feature is free.
static void
test_maintenance_can_be_turned_off(void)
{
    n00b_store_zone_maps_set_enabled(false);

    n00b_store_t *store = open_store(new_memory_vfs());
    build_four_shards(store);

    // Every shard is read, including for a range no shard's values reach.
    uint64_t records = 0;
    CHECK(shards_read(store, predicate_range(r"ts", 900, 999), &records) == 4);
    CHECK(records == 0);
    CHECK(shards_read(store, predicate_range(r"ts", 102, 105), &records) == 4);
    CHECK(records == 4);

    // And the coverage report says why rather than leaving it to be guessed
    // from the shard count.
    auto cov_r = n00b_store_zone_coverage(store, r"ts");
    CHECK(n00b_result_is_ok(cov_r));
    CHECK(n00b_result_get(cov_r).shards == 4);
    CHECK(n00b_result_get(cov_r).with_bounds == 0);

    // Restored before anything else runs: the switch is process-wide.
    n00b_store_zone_maps_set_enabled(true);

    n00b_store_t *after = open_store(new_memory_vfs());
    build_four_shards(after);
    CHECK(shards_read(after, predicate_range(r"ts", 900, 999), &records) == 0);
}

// ---------------------------------------------------------------------------
// Catalog format.
//
// Bounds are catalog metadata, so the catalog's compatibility rules are what
// decide whether a store written by one build opens under another. Until now
// that rested entirely on reading the version gate and believing it.
// ---------------------------------------------------------------------------

// Whole-file helpers over the VFS handle API, so the format tests can read
// and rewrite the catalog the way the store does.
static n00b_buffer_t *
vfs_slurp(n00b_vfs_t *vfs, n00b_string_t *path)
{
    auto stat_r = n00b_vfs_stat(vfs, path);
    CHECK(n00b_result_is_ok(stat_r));
    uint64_t size = (uint64_t)n00b_result_get(stat_r).size;

    auto open_r = n00b_vfs_open(vfs, path, N00B_VFS_O_R);
    CHECK(n00b_result_is_ok(open_r));
    n00b_vfs_fh_t fh = n00b_result_get(open_r);

    auto read_r = n00b_vfs_read(vfs, fh, size);
    CHECK(n00b_result_is_ok(read_r));
    (void)n00b_vfs_close(vfs, fh);
    return n00b_result_get(read_r);
}

static void
vfs_replace(n00b_vfs_t *vfs, n00b_string_t *path, n00b_buffer_t *data)
{
    auto open_r = n00b_vfs_open(vfs, path, N00B_VFS_O_W);
    CHECK(n00b_result_is_ok(open_r));
    n00b_vfs_fh_t fh = n00b_result_get(open_r);
    CHECK(n00b_result_is_ok(n00b_vfs_write(vfs, fh, data)));
    (void)n00b_vfs_close(vfs, fh);
}

static uint64_t
catalog_version_of(n00b_vfs_t *vfs)
{
    n00b_buffer_t *buf = vfs_slurp(vfs, r"/rocs/catalog.rocs");

    // magic is 8 bytes, then the version as a little-endian u64.
    CHECK(n00b_buffer_len(buf) >= 16);
    uint64_t version = 0;
    for (int i = 7; i >= 0; i--) {
        version = (version << 8) | (uint64_t)(uint8_t)buf->data[8 + i];
    }
    return version;
}

// Rewrite a catalog as the previous version would have written it: drop the
// per-entry zone section and set the version back.
//
// This is what a store written before bounds existed looks like, produced from
// one written now rather than checked in as bytes. A checked-in file would rot
// the first time an unrelated field moved, and would say nothing about which
// part of the format changed.
static void
downgrade_catalog_to_v3(n00b_vfs_t *vfs)
{
    n00b_buffer_t *in = vfs_slurp(vfs, r"/rocs/catalog.rocs");

    int64_t  len = n00b_buffer_len(in);
    uint8_t *out = n00b_alloc_array(uint8_t, len);
    int64_t  n   = 0;

    // Header: magic, version, generation, next id, schema gen, oldest triple,
    // entry count.
    for (int64_t i = 0; i < 8; i++) {
        out[n++] = (uint8_t)in->data[i];
    }
    // Version 3, little endian.
    out[n++] = 3;
    for (int64_t i = 1; i < 8; i++) {
        out[n++] = 0;
    }

    // generation, next open shard id, schema generation, the oldest-available
    // triple, then the entry count: seven in all.
    int64_t pos = 16;
    for (int64_t f = 0; f < 7; f++) {
        for (int64_t i = 0; i < 8; i++) {
            out[n++] = (uint8_t)in->data[pos++];
        }
    }

    uint64_t entries = 0;
    for (int i = 7; i >= 0; i--) {
        entries = (entries << 8) | (uint64_t)(uint8_t)in->data[pos - 8 + i];
    }

    for (uint64_t e = 0; e < entries; e++) {
        // state, shard id, generation, bytes, records, schema gen, seal ts.
        for (int64_t f = 0; f < 7; f++) {
            for (int64_t i = 0; i < 8; i++) {
                out[n++] = (uint8_t)in->data[pos++];
            }
        }
        // Three length-prefixed strings.
        for (int64_t sN = 0; sN < 3; sN++) {
            uint64_t slen = 0;
            for (int i = 7; i >= 0; i--) {
                slen = (slen << 8) | (uint64_t)(uint8_t)in->data[pos + i];
            }
            for (int64_t i = 0; i < 8; i++) {
                out[n++] = (uint8_t)in->data[pos++];
            }
            for (uint64_t i = 0; i < slen; i++) {
                out[n++] = (uint8_t)in->data[pos++];
            }
        }

        // The zone section a v3 writer would not have written: read past it
        // without copying it.
        uint64_t zones = 0;
        for (int i = 7; i >= 0; i--) {
            zones = (zones << 8) | (uint64_t)(uint8_t)in->data[pos + i];
        }
        pos += 8;
        for (uint64_t z = 0; z < zones; z++) {
            uint64_t flen = 0;
            for (int i = 7; i >= 0; i--) {
                flen = (flen << 8) | (uint64_t)(uint8_t)in->data[pos + i];
            }
            pos += 8 + (int64_t)flen;
            for (int64_t bound = 0; bound < 2; bound++) {
                uint8_t kind = (uint8_t)in->data[pos++];
                if (kind == 3) {
                    uint64_t vlen = 0;
                    for (int i = 7; i >= 0; i--) {
                        vlen = (vlen << 8) | (uint64_t)(uint8_t)in->data[pos + i];
                    }
                    pos += 8 + (int64_t)vlen;
                }
                else {
                    pos += 8;
                }
            }
        }
    }

    CHECK(pos == len);
    vfs_replace(vfs,
                r"/rocs/catalog.rocs",
                n00b_buffer_from_bytes((char *)out, n));
}

static void
test_catalog_round_trips_and_opens_a_v3(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs();
    n00b_store_t *store = open_store(vfs);
    build_four_shards(store);
    CHECK(n00b_result_is_ok(n00b_store_close(store)));

    // What this build writes.
    CHECK(catalog_version_of(vfs) == 4);

    // And reads back, bounds included.
    n00b_store_t *reopened = open_store(vfs);
    uint64_t      records  = 0;
    CHECK(shards_read(reopened, predicate_range(r"ts", 102, 105), &records)
          == 1);
    CHECK(n00b_result_is_ok(n00b_store_close(reopened)));

    // A catalog from before bounds existed still opens, and answers the same
    // queries. It prunes nothing, which is the whole compatibility claim: an
    // older store is slower here, never wrong.
    downgrade_catalog_to_v3(vfs);
    CHECK(catalog_version_of(vfs) == 3);

    n00b_store_t *old = open_store(vfs);
    CHECK(shards_read(old, predicate_range(r"ts", 102, 105), &records) == 4);
    CHECK(records == 4);
    CHECK(shards_read(old, predicate_range(r"ts", 900, 999), &records) == 4);
    CHECK(records == 0);

    // And sealing a new shard into it writes the current version again.
    ingest(old, record_ts(9001, 9001));
    seal(old, 2000);
    CHECK(catalog_version_of(vfs) == 4);
}

static void
test_zone_coverage_reports_the_gap(void)
{
    n00b_store_t *store = open_store(new_memory_vfs());
    build_four_shards(store);

    auto cov_r = n00b_store_zone_coverage(store, r"ts");
    CHECK(n00b_result_is_ok(cov_r));
    n00b_store_zone_coverage_t cov = n00b_result_get(cov_r);
    CHECK(cov.shards == 4);
    CHECK(cov.with_bounds == 4);

    // A field no record carried has no interval anywhere, and the count says
    // so rather than the query silently reading everything.
    auto none_r = n00b_store_zone_coverage(store, r"absent");
    CHECK(n00b_result_is_ok(none_r));
    CHECK(n00b_result_get(none_r).shards == 4);
    CHECK(n00b_result_get(none_r).with_bounds == 0);

    // The case the report is actually for: a partial gap, where some shards
    // can be skipped on the field and the rest have to be opened. A count of
    // zero and a count of every shard are both easy to notice; this is the
    // one that otherwise shows up only as a query being slower than expected.
    n00b_store_t *mixed = open_store(new_memory_vfs());
    ingest(mixed, record_host(1, r"alpha"));
    seal(mixed, 2000);

    n00b_json_node_t *odd = n00b_json_object_new();
    n00b_json_object_put_n00b(odd, r"id", n00b_json_int_new(2));
    n00b_json_object_put_n00b(odd, r"host", n00b_json_int_new(7));
    ingest(mixed, odd);
    ingest(mixed, record_host(3, r"beta"));
    seal(mixed, 2001);

    ingest(mixed, record_ts(4, 1));
    seal(mixed, 2002);

    auto partial_r = n00b_store_zone_coverage(mixed, r"host");
    CHECK(n00b_result_is_ok(partial_r));
    n00b_store_zone_coverage_t partial = n00b_result_get(partial_r);
    // Three shards: one with a string interval, one that saw both a string
    // and a number and so has none, one that never carried the field.
    CHECK(partial.shards == 3);
    CHECK(partial.with_bounds == 1);
}

// A seal that fails between rotation and the catalog commit must not lose the
// shard's bounds, and must not hand them to the shard that replaced it.
//
// That window is where the hand-off is: the sealed shard has been detached and
// its interval has moved onto the seal job, the replacement is already taking
// ingest, and the catalog describes neither yet. Losing the interval there
// leaves a shard that is correct and never prunable again; copying it to the
// replacement would make the replacement claim values it does not hold, which
// is the one direction that skips a shard holding matches.
//
// Driven by a size-triggered rotation rather than an explicit seal, because
// only the ingest hot path defers to the seal pool. An explicit
// n00b_store_seal_hot_shard seals inline, never builds a job, and so never
// reaches the window this is about.
static void
test_a_failed_seal_keeps_its_bounds(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_schema_t *schema = n00b_result_get(schema_r);
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"ts")));

    auto policy_r = n00b_store_seal_policy_new(.max_records = 10);
    CHECK(n00b_result_is_ok(policy_r));

    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs",
                                       schema,
                                       .seal_policy  = n00b_result_get(policy_r),
                                       .keep_standby = true);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    // Shard one: ts 0..9, rotated by the size trigger on the tenth.
    n00b_store_seal_force_next_failure(true);
    for (int64_t i = 0; i < 10; i++) {
        ingest(store, record_ts(i, i));
    }

    // Shard two, into the replacement: ts 500..509. Had the rotation left the
    // outgoing shard's bounds on the store, these would widen them and both
    // shards would end up claiming [0, 509].
    for (int64_t i = 500; i < 510; i++) {
        ingest(store, record_ts(i, i));
    }

    // Drains the queue and retries whatever failed, which is where the
    // retained bounds are picked back up.
    CHECK(n00b_result_is_ok(n00b_store_flush(store)));

    auto count_r = n00b_store_catalog_visible_entry_count(store);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) >= 2);

    uint64_t records = 0;

    // The shard whose seal failed still prunes, so its interval survived both
    // the failure and the retry.
    CHECK(shards_read(store, predicate_range(r"ts", 2, 5), &records) == 1);
    CHECK(records == 4);

    // The replacement carries its own interval rather than the one it
    // replaced: a range over the first shard's values must not reach it.
    CHECK(shards_read(store, predicate_range(r"ts", 502, 505), &records) == 1);
    CHECK(records == 4);

    // Neither claims the gap between them.
    CHECK(shards_read(store, predicate_range(r"ts", 100, 200), &records) == 0);
    CHECK(records == 0);

    // Closed explicitly: keep_standby runs a seal worker thread, and shutdown
    // waits on it. Every other store here is inline-sealed and leaves none.
    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_range_skips_shards();
    test_bound_edges_are_respected();
    test_exclusive_bounds_decide_the_touching_case();
    test_composite_predicates_prune();
    test_rewritten_predicates_reach_the_filter();
    test_equality_prunes_too();
    test_unprunable_predicates_read_everything();
    test_mixed_types_disable_the_field();
    test_bounds_survive_a_reopen();
    test_string_bounds();
    test_double_bounds();
    test_maintenance_can_be_turned_off();
    test_catalog_round_trips_and_opens_a_v3();
    test_zone_coverage_reports_the_gap();
    test_a_failed_seal_keeps_its_bounds();

    n00b_shutdown();
    return 0;
}
