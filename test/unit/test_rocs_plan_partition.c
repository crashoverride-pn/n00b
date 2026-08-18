/* test/unit/test_rocs_plan_partition.c - WP-006 Phase 5 shard planning. */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>

#ifdef N00B_ROCS_INTERNAL_PLAN_H
#error "internal planner declarations must not be included by rocs/n00b_rocs.h"
#endif

#include "internal/rocs/plan_ir.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

static n00b_plan_value_t
json_value(n00b_json_node_t *node)
{
    return n00b_variant_set(n00b_plan_value_t, n00b_json_node_t *, node);
}

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

static n00b_store_schema_t *
new_schema(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    return n00b_result_get(schema_r);
}

static n00b_store_t *
open_store(n00b_vfs_t *vfs) _kargs
{
    n00b_store_partition_policy_t *partition_policy = nullptr;
}
{
    auto store_r = n00b_store_open_vfs(vfs,
                                       r"/rocs",
                                       new_schema(),
                                       .partition_policy = partition_policy);
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_json_node_t *
record_id_kind(int64_t id, n00b_string_t *kind)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    if (kind != nullptr) {
        n00b_json_object_put_n00b(record,
                                  r"kind",
                                  n00b_json_string_new_from_n00b(kind));
    }
    return record;
}

static n00b_json_node_t *
record_ts_kind(int64_t id, int64_t ts, n00b_string_t *kind)
{
    n00b_json_node_t *record = record_id_kind(id, kind);
    n00b_json_object_put_n00b(record, r"ts", n00b_json_int_new(ts));
    return record;
}

static n00b_json_node_t *
record_ts_string_kind(int64_t id, n00b_string_t *ts, n00b_string_t *kind)
{
    n00b_json_node_t *record = record_id_kind(id, kind);
    n00b_json_object_put_n00b(record,
                              r"ts",
                              n00b_json_string_new_from_n00b(ts));
    return record;
}

static n00b_json_node_t *
record_user(n00b_string_t *user)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record,
                              r"user",
                              n00b_json_string_new_from_n00b(user));
    return record;
}

static n00b_store_catalog_entry_t *
ingest_and_seal(n00b_store_t     *store,
                n00b_json_node_t *record,
                uint64_t          seal_ts)
{
    auto ingest_r = n00b_store_ingest(store, record);
    CHECK(n00b_result_is_ok(ingest_r));

    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = seal_ts);
    CHECK(n00b_result_is_ok(seal_r));
    return n00b_result_get(seal_r);
}

static n00b_plan_target_t *
field_target(n00b_string_t *field)
{
    auto target_r = n00b_plan_target_field(field);
    CHECK(n00b_result_is_ok(target_r));
    return n00b_result_get(target_r);
}

static n00b_plan_predicate_t *
predicate_eq(n00b_string_t *field, n00b_json_node_t *value)
{
    auto pred_r = n00b_plan_predicate_eq(field_target(field),
                                         json_value(value));
    CHECK(n00b_result_is_ok(pred_r));
    return n00b_result_get(pred_r);
}

static n00b_plan_predicate_t *
predicate_exists(n00b_string_t *field)
{
    auto pred_r = n00b_plan_predicate_exists(field_target(field));
    CHECK(n00b_result_is_ok(pred_r));
    return n00b_result_get(pred_r);
}

static n00b_plan_predicate_t *
predicate_or(n00b_plan_predicate_t *left, n00b_plan_predicate_t *right)
{
    n00b_plan_predicate_list_t *children = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(children, left)));
    CHECK(n00b_result_is_ok(n00b_plan_predicate_list_append(children, right)));
    auto pred_r = n00b_plan_predicate_or(children);
    CHECK(n00b_result_is_ok(pred_r));
    return n00b_result_get(pred_r);
}

static n00b_plan_predicate_t *
predicate_not(n00b_plan_predicate_t *child)
{
    auto pred_r = n00b_plan_predicate_not(child);
    CHECK(n00b_result_is_ok(pred_r));
    return n00b_result_get(pred_r);
}

static n00b_plan_shard_result_list_t *
plan_ok(n00b_store_t *store, n00b_plan_predicate_t *predicate)
{
    auto plan_r = n00b_plan_store_sealed(store, predicate, nullptr);
    CHECK(n00b_result_is_ok(plan_r));
    return n00b_result_get(plan_r);
}

static uint64_t
result_count(n00b_plan_shard_result_list_t *results)
{
    auto count_r = n00b_plan_shard_result_count(results);
    CHECK(n00b_result_is_ok(count_r));
    return n00b_result_get(count_r);
}

static n00b_plan_shard_result_t *
result_at(n00b_plan_shard_result_list_t *results, uint64_t index)
{
    auto result_r = n00b_plan_shard_result_at(results, index);
    CHECK(n00b_result_is_ok(result_r));
    CHECK(n00b_option_is_set(n00b_result_get(result_r)));
    return n00b_option_get(n00b_result_get(result_r));
}

static bool
expected_has(const uint64_t *expected, uint64_t len, uint64_t ordinal)
{
    for (uint64_t i = 0; i < len; i++) {
        if (expected[i] == ordinal) {
            return true;
        }
    }
    return false;
}

static void
check_set(n00b_plan_ordset_t *set,
          uint64_t            record_count,
          const uint64_t     *expected,
          uint64_t            expected_len)
{
    auto record_count_r = n00b_plan_ordset_record_count(set);
    CHECK(n00b_result_is_ok(record_count_r));
    CHECK(n00b_result_get(record_count_r) == record_count);

    auto count_r = n00b_plan_ordset_count(set);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == expected_len);

    for (uint64_t i = 0; i < expected_len; i++) {
        auto at_r = n00b_plan_ordset_at(set, i);
        CHECK(n00b_result_is_ok(at_r));
        CHECK(n00b_option_is_set(n00b_result_get(at_r)));
        CHECK(n00b_option_get(n00b_result_get(at_r)) == expected[i]);
    }

    auto none_r = n00b_plan_ordset_at(set, expected_len);
    CHECK(n00b_result_is_ok(none_r));
    CHECK(!n00b_option_is_set(n00b_result_get(none_r)));

    for (uint64_t ordinal = 0; ordinal < record_count; ordinal++) {
        auto contains_r = n00b_plan_ordset_contains(set, ordinal);
        CHECK(n00b_result_is_ok(contains_r));
        CHECK(n00b_result_get(contains_r)
              == expected_has(expected, expected_len, ordinal));
    }
}

static void
check_no_active_pins(n00b_store_t *store)
{
    auto pins_r = n00b_store_get_active_pins(store);
    CHECK(n00b_result_is_ok(pins_r));
    CHECK(n00b_result_get(pins_r) == 0);
}

static void
check_result_matches_entry(n00b_plan_shard_result_t    *result,
                           n00b_store_catalog_entry_t  *entry,
                           const uint64_t              *expected,
                           uint64_t                     expected_len)
{
    auto result_id_r = n00b_plan_shard_result_shard_id(result);
    auto entry_id_r  = n00b_store_catalog_entry_get_shard_id(entry);
    CHECK(n00b_result_is_ok(result_id_r));
    CHECK(n00b_result_is_ok(entry_id_r));
    CHECK(n00b_result_get(result_id_r) == n00b_result_get(entry_id_r));

    auto result_gen_r = n00b_plan_shard_result_generation(result);
    auto entry_gen_r  = n00b_store_catalog_entry_get_generation(entry);
    CHECK(n00b_result_is_ok(result_gen_r));
    CHECK(n00b_result_is_ok(entry_gen_r));
    CHECK(n00b_result_get(result_gen_r) == n00b_result_get(entry_gen_r));

    auto result_schema_r =
        n00b_plan_shard_result_schema_generation(result);
    auto entry_schema_r =
        n00b_store_catalog_entry_get_schema_generation(entry);
    CHECK(n00b_result_is_ok(result_schema_r));
    CHECK(n00b_result_is_ok(entry_schema_r));
    CHECK(n00b_result_get(result_schema_r)
          == n00b_result_get(entry_schema_r));

    auto result_records_r = n00b_plan_shard_result_record_count(result);
    auto entry_records_r  = n00b_store_catalog_entry_get_record_count(entry);
    CHECK(n00b_result_is_ok(result_records_r));
    CHECK(n00b_result_is_ok(entry_records_r));
    CHECK(n00b_result_get(result_records_r)
          == n00b_result_get(entry_records_r));

    auto result_seal_r = n00b_plan_shard_result_seal_ts(result);
    auto entry_seal_r  = n00b_store_catalog_entry_get_seal_ts(entry);
    CHECK(n00b_result_is_ok(result_seal_r));
    CHECK(n00b_result_is_ok(entry_seal_r));
    CHECK(n00b_result_get(result_seal_r) == n00b_result_get(entry_seal_r));

    auto result_part_r = n00b_plan_shard_result_partition_key(result);
    auto entry_part_r  = n00b_store_catalog_entry_get_partition_key(entry);
    CHECK(n00b_result_is_ok(result_part_r));
    CHECK(n00b_result_is_ok(entry_part_r));
    CHECK(n00b_unicode_str_eq(n00b_result_get(result_part_r),
                              n00b_result_get(entry_part_r)));

    auto ordinals_r = n00b_plan_shard_result_ordinals(result);
    CHECK(n00b_result_is_ok(ordinals_r));
    check_set(n00b_result_get(ordinals_r),
              n00b_result_get(entry_records_r),
              expected,
              expected_len);
}

static n00b_store_catalog_entry_t *
find_entry(n00b_store_t *store, uint64_t shard_id)
{
    auto find_r = n00b_store_catalog_find_shard(store, shard_id);
    CHECK(n00b_result_is_ok(find_r));
    CHECK(n00b_option_is_set(n00b_result_get(find_r)));
    return n00b_option_get(n00b_result_get(find_r));
}

static void
test_time_and_default_partition_pruning(void)
{
    auto policy_r = n00b_store_partition_policy_new_time(r"ts", 10, N00B_STORE_TIME_SOURCE_RECORD_FIELD);
    CHECK(n00b_result_is_ok(policy_r));
    n00b_store_t *store = open_store(new_memory_vfs(),
                                     .partition_policy = n00b_result_get(policy_r));

    n00b_store_catalog_entry_t *first =
        ingest_and_seal(store, record_ts_kind(1, 5, r"cold"), 101);
    n00b_store_catalog_entry_t *second =
        ingest_and_seal(store, record_ts_kind(2, 15, r"hot"), 102);
    n00b_store_catalog_entry_t *third =
        ingest_and_seal(store, record_ts_string_kind(3, r"late", r"cold"), 103);

    n00b_plan_shard_result_list_t *time_results =
        plan_ok(store, predicate_eq(r"ts", n00b_json_int_new(15)));
    CHECK(result_count(time_results) == 1);
    uint64_t only[] = {0};
    check_result_matches_entry(result_at(time_results, 0), second, only, 1);
    check_no_active_pins(store);

    auto resident_r = n00b_store_get_resident_shard_count(store);
    CHECK(n00b_result_is_ok(resident_r));
    CHECK(n00b_result_get(resident_r) == 1);

    n00b_plan_shard_result_list_t *default_results =
        plan_ok(store,
                predicate_eq(r"ts",
                             n00b_json_string_new_from_n00b(r"late")));
    CHECK(result_count(default_results) == 1);
    check_result_matches_entry(result_at(default_results, 0), third, only, 1);
    check_no_active_pins(store);

    auto first_part_r = n00b_store_catalog_entry_get_partition_key(first);
    CHECK(n00b_result_is_ok(first_part_r));
    CHECK(n00b_unicode_str_eq(n00b_result_get(first_part_r), r"time/0"));
}

static n00b_string_t *
route_for_user(n00b_store_partition_policy_t *policy, n00b_string_t *user)
{
    auto route_r = n00b_store_partition_route(policy, record_user(user));
    CHECK(n00b_result_is_ok(route_r));
    return n00b_result_get(route_r);
}

static void
pick_distinct_hash_values(n00b_store_partition_policy_t *policy,
                          n00b_string_t                **first,
                          n00b_string_t                **second)
{
    n00b_string_t *values[] = {
        r"alpha", r"bravo", r"charlie", r"delta",
        r"echo",  r"foxtrot", r"golf",    r"hotel",
    };

    for (uint64_t i = 0; i < 8; i++) {
        for (uint64_t j = i + 1; j < 8; j++) {
            n00b_string_t *left_route = route_for_user(policy, values[i]);
            n00b_string_t *right_route = route_for_user(policy, values[j]);
            if (!n00b_unicode_str_eq(left_route, right_route)) {
                *first  = values[i];
                *second = values[j];
                return;
            }
        }
    }

    CHECK(false);
}

static void
test_hash_partition_pruning(void)
{
    auto policy_r = n00b_store_partition_policy_new_hash(r"user", 128);
    CHECK(n00b_result_is_ok(policy_r));
    n00b_store_partition_policy_t *policy = n00b_result_get(policy_r);

    n00b_string_t *first_user  = nullptr;
    n00b_string_t *second_user = nullptr;
    pick_distinct_hash_values(policy, &first_user, &second_user);

    n00b_store_t *store = open_store(new_memory_vfs(),
                                     .partition_policy = policy);
    n00b_store_catalog_entry_t *first =
        ingest_and_seal(store, record_user(first_user), 201);
    ingest_and_seal(store, record_user(second_user), 202);

    n00b_plan_shard_result_list_t *results =
        plan_ok(store,
                predicate_eq(r"user",
                             n00b_json_string_new_from_n00b(first_user)));
    CHECK(result_count(results) == 1);
    uint64_t only[] = {0};
    check_result_matches_entry(result_at(results, 0), first, only, 1);
    check_no_active_pins(store);

    auto resident_r = n00b_store_get_resident_shard_count(store);
    CHECK(n00b_result_is_ok(resident_r));
    CHECK(n00b_result_get(resident_r) == 1);
}

static n00b_store_t *
new_three_partition_time_store(n00b_store_catalog_entry_t **first,
                               n00b_store_catalog_entry_t **second,
                               n00b_store_catalog_entry_t **third)
{
    auto policy_r = n00b_store_partition_policy_new_time(r"ts", 10, N00B_STORE_TIME_SOURCE_RECORD_FIELD);
    CHECK(n00b_result_is_ok(policy_r));
    n00b_store_t *store = open_store(new_memory_vfs(),
                                     .partition_policy = n00b_result_get(policy_r));

    *first  = ingest_and_seal(store, record_ts_kind(1, 5, r"cold"), 301);
    *second = ingest_and_seal(store, record_ts_kind(2, 15, r"keep"), 302);
    *third  = ingest_and_seal(store,
                              record_ts_string_kind(3, r"late", r"cold"),
                              303);
    return store;
}

static void
check_ordered_ids(n00b_plan_shard_result_list_t *results,
                  uint64_t                       a,
                  uint64_t                       b,
                  uint64_t                       c)
{
    auto id0_r = n00b_plan_shard_result_shard_id(result_at(results, 0));
    auto id1_r = n00b_plan_shard_result_shard_id(result_at(results, 1));
    auto id2_r = n00b_plan_shard_result_shard_id(result_at(results, 2));
    CHECK(n00b_result_is_ok(id0_r));
    CHECK(n00b_result_is_ok(id1_r));
    CHECK(n00b_result_is_ok(id2_r));
    CHECK(n00b_result_get(id0_r) == a);
    CHECK(n00b_result_get(id1_r) == b);
    CHECK(n00b_result_get(id2_r) == c);
}

static void
test_unsafe_or_not_keep_all_and_ordering(void)
{
    n00b_store_catalog_entry_t *first  = nullptr;
    n00b_store_catalog_entry_t *second = nullptr;
    n00b_store_catalog_entry_t *third  = nullptr;
    n00b_store_t *store =
        new_three_partition_time_store(&first, &second, &third);

    n00b_plan_predicate_t *or_pred =
        predicate_or(predicate_eq(r"ts", n00b_json_int_new(5)),
                     predicate_eq(r"kind",
                                  n00b_json_string_new_from_n00b(r"keep")));
    n00b_plan_shard_result_list_t *or_results = plan_ok(store, or_pred);
    CHECK(result_count(or_results) == 3);
    check_ordered_ids(or_results, 1, 2, 3);

    uint64_t one[] = {0};
    check_result_matches_entry(result_at(or_results, 0), first, one, 1);
    check_result_matches_entry(result_at(or_results, 1), second, one, 1);
    check_result_matches_entry(result_at(or_results, 2), third, nullptr, 0);
    check_no_active_pins(store);

    auto resident_r = n00b_store_get_resident_shard_count(store);
    CHECK(n00b_result_is_ok(resident_r));
    CHECK(n00b_result_get(resident_r) == 3);

    n00b_plan_predicate_t *not_pred =
        predicate_not(predicate_eq(r"ts", n00b_json_int_new(5)));
    n00b_plan_shard_result_list_t *not_results = plan_ok(store, not_pred);
    CHECK(result_count(not_results) == 3);
    check_ordered_ids(not_results, 1, 2, 3);
    check_result_matches_entry(result_at(not_results, 0), first, nullptr, 0);
    check_result_matches_entry(result_at(not_results, 1), second, one, 1);
    check_result_matches_entry(result_at(not_results, 2), third, one, 1);
    check_no_active_pins(store);
}

static void
test_catalog_visible_only_and_dropped_exclusion(void)
{
    n00b_vfs_t   *vfs   = new_memory_vfs();
    n00b_store_t *store = open_store(vfs);

    n00b_store_catalog_entry_t *first =
        ingest_and_seal(store, record_id_kind(1, r"visible"), 401);

    auto ingest_hot_r = n00b_store_ingest(store, record_id_kind(2, r"hot"));
    CHECK(n00b_result_is_ok(ingest_hot_r));

    n00b_plan_shard_result_list_t *visible_only =
        plan_ok(store, predicate_exists(r"id"));
    CHECK(result_count(visible_only) == 1);
    uint64_t one[] = {0};
    check_result_matches_entry(result_at(visible_only, 0), first, one, 1);
    check_no_active_pins(store);

    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = 402);
    CHECK(n00b_result_is_ok(seal_r));
    n00b_store_catalog_entry_t *second = n00b_result_get(seal_r);

    auto drop_r = n00b_store_drop_sealed_shard(store, 1);
    CHECK(n00b_result_is_ok(drop_r));

    n00b_plan_shard_result_list_t *after_drop =
        plan_ok(store, predicate_exists(r"id"));
    CHECK(result_count(after_drop) == 1);
    check_result_matches_entry(result_at(after_drop, 0), second, one, 1);
    check_no_active_pins(store);

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));

    n00b_store_t *reopened = open_store(vfs);
    n00b_plan_shard_result_list_t *after_reopen =
        plan_ok(reopened, predicate_exists(r"id"));
    CHECK(result_count(after_reopen) == 1);
    check_result_matches_entry(result_at(after_reopen, 0),
                               find_entry(reopened, 2),
                               one,
                               1);
    check_no_active_pins(reopened);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_time_and_default_partition_pruning();
    test_hash_partition_pruning();
    test_unsafe_or_not_keep_all_and_ordering();
    test_catalog_visible_only_and_dropped_exclusion();

    n00b_shutdown();
    return 0;
}
