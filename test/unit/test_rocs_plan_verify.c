/* test/unit/test_rocs_plan_verify.c - WP-006 Phase 4 residual verification. */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>

#ifdef N00B_ROCS_INTERNAL_PLAN_H
#error "internal planner declarations must not be included by rocs/n00b_rocs.h"
#endif

#include "internal/rocs/plan_ir.h"
#include "internal/rocs/eval.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

#include "plan_oracle.h"

#define CHECK_ERR(expr, expected)                                              \
    do {                                                                       \
        auto _bl_check_err_result = (expr);                                    \
        CHECK(n00b_result_is_err(_bl_check_err_result));                       \
        CHECK(n00b_result_get_err(_bl_check_err_result) == (expected));        \
    } while (0)

static n00b_plan_value_t
json_value(n00b_json_node_t *node)
{
    return n00b_variant_set(n00b_plan_value_t, n00b_json_node_t *, node);
}

static n00b_store_index_t *
index_ok(n00b_result_t(n00b_store_index_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_store_index_t *index = n00b_result_get(r);
    CHECK(index != nullptr);
    return index;
}

static n00b_plan_target_t *
target_ok(n00b_result_t(n00b_plan_target_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_target_t *target = n00b_result_get(r);
    CHECK(target != nullptr);
    return target;
}

static n00b_plan_predicate_t *
predicate_ok(n00b_result_t(n00b_plan_predicate_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_predicate_t *predicate = n00b_result_get(r);
    CHECK(predicate != nullptr);
    return predicate;
}

static n00b_plan_ordset_t *
ordset_ok_expr(n00b_result_t(n00b_plan_ordset_t *) r, const char *expr)
{
    n00b_require(n00b_result_is_ok(r), expr);
    n00b_plan_ordset_t *set = n00b_result_get(r);
    CHECK(set != nullptr);
    return set;
}

#define ordset_ok(expr) ordset_ok_expr((expr), #expr)

static n00b_plan_node_t *
plan_ok(n00b_result_t(n00b_plan_node_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_plan_node_t *plan = n00b_result_get(r);
    CHECK(plan != nullptr);
    return plan;
}

static n00b_regex_t *
regex_ok(n00b_result_t(n00b_regex_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_regex_t *regex = n00b_result_get(r);
    CHECK(regex != nullptr);
    return regex;
}

static n00b_plan_target_t *
field_target(n00b_string_t *field)
{
    return target_ok(n00b_plan_target_field(field));
}

static n00b_plan_index_list_t *
index_list_with(n00b_store_index_t *index)
{
    n00b_plan_index_list_t *indexes = n00b_plan_index_list_new();
    CHECK(n00b_result_is_ok(n00b_plan_index_list_append(indexes, index)));
    return indexes;
}

static n00b_store_index_t *
term_index(n00b_string_t *field)
{
    return index_ok(n00b_store_index_new(field, N00B_STORE_INDEX_TERM));
}

static n00b_json_node_t *
payload_node(n00b_string_t *message)
{
    n00b_json_node_t *payload = n00b_json_object_new();
    n00b_json_node_t *items   = n00b_json_array_new();
    n00b_json_node_t *item    = n00b_json_object_new();
    n00b_json_object_put_n00b(item,
                              r"message",
                              n00b_json_string_new_from_n00b(message));
    n00b_json_array_push(items, item);
    n00b_json_object_put_n00b(payload, r"items", items);
    return payload;
}

static n00b_json_node_t *
record_with_fields(n00b_string_t *level,
                   n00b_string_t *message,
                   int64_t        status,
                   int64_t        latency,
                   bool           latency_as_string,
                   bool           include_payload)
{
    n00b_json_node_t *record = n00b_json_object_new();
    if (level != nullptr) {
        n00b_json_object_put_n00b(record,
                                  r"level",
                                  n00b_json_string_new_from_n00b(level));
    }
    n00b_json_object_put_n00b(record,
                              r"message",
                              n00b_json_string_new_from_n00b(message));
    n00b_json_object_put_n00b(record, r"status", n00b_json_int_new(status));
    if (latency_as_string) {
        n00b_json_object_put_n00b(record,
                                  r"latency_ms",
                                  n00b_json_string_new_from_n00b(r"slow"));
    }
    else {
        n00b_json_object_put_n00b(record,
                                  r"latency_ms",
                                  n00b_json_int_new(latency));
    }
    if (include_payload) {
        n00b_json_object_put_n00b(record,
                                  r"payload",
                                  payload_node(message));
    }
    return record;
}

static n00b_store_shard_t *
sample_shard(n00b_store_index_t *index)
{
    auto shard_r = n00b_store_shard_new(.shard_id = UINT64_C(0x700d));
    CHECK(n00b_result_is_ok(shard_r));
    n00b_store_shard_t *shard = n00b_result_get(shard_r);

    n00b_json_node_t *records[] = {
        record_with_fields(r"info",
                           r"startup complete",
                           200,
                           12,
                           false,
                           true),
        record_with_fields(r"error",
                           r"timeout while opening",
                           500,
                           75,
                           false,
                           true),
        record_with_fields(r"error",
                           r"disk full",
                           507,
                           130,
                           false,
                           true),
        record_with_fields(nullptr,
                           r"message without level",
                           204,
                           0,
                           true,
                           false),
    };

    for (uint64_t i = 0; i < 4; i++) {
        auto append_r = n00b_store_shard_append(shard, records[i]);
        CHECK(n00b_result_is_ok(append_r));
        CHECK(n00b_result_get(append_r) == i);
        if (index != nullptr) {
            auto add_r = n00b_store_index_add(index, shard, i);
            CHECK(n00b_result_is_ok(add_r));
        }
    }

    return shard;
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

static n00b_plan_ordset_t *
candidate_set(const uint64_t *ordinals, uint64_t len)
{
    n00b_plan_ordset_t *set = ordset_ok(n00b_plan_ordset_empty(4));
    for (uint64_t i = 0; i < len; i++) {
        CHECK(n00b_result_is_ok(n00b_plan_ordset_insert(set, ordinals[i])));
    }
    return set;
}

static n00b_plan_predicate_t *
level_eq_error(void)
{
    return predicate_ok(
        n00b_plan_predicate_eq(field_target(r"level"),
                               json_value(n00b_json_string_new_from_n00b(r"error"))));
}

static n00b_plan_predicate_t *
message_prefix_timeout(void)
{
    return predicate_ok(n00b_plan_predicate_prefix(field_target(r"message"),
                                                  r"timeout"));
}

static n00b_plan_path_t *
payload_message_path(uint64_t item_index)
{
    n00b_plan_path_component_list_t *components =
        n00b_plan_path_component_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_path_component_list_append_key(components, r"items")));
    CHECK(n00b_result_is_ok(
        n00b_plan_path_component_list_append_index(components, item_index)));
    CHECK(n00b_result_is_ok(
        n00b_plan_path_component_list_append_key(components, r"message")));

    auto path_r = n00b_plan_path_new(components);
    CHECK(n00b_result_is_ok(path_r));
    return n00b_result_get(path_r);
}

static void
test_no_index_plans_a_record_scan(void)
{
    n00b_store_shard_t    *shard = sample_shard(nullptr);
    n00b_plan_predicate_t *prefix = message_prefix_timeout();

    n00b_plan_node_t *plan = plan_ok(n00b_plan_build(prefix, nullptr));

    // With no index there is nothing to narrow with, so the plan is a bare
    // record scan and execution goes straight to the matching records.
    auto record_scan_r = n00b_plan_sole_record_scan(plan);
    CHECK(n00b_result_is_ok(record_scan_r));
    CHECK(n00b_option_is_set(n00b_result_get(record_scan_r)));
    CHECK(n00b_option_get(n00b_result_get(record_scan_r)) == prefix);

    n00b_plan_ordset_t *verified =
        ordset_ok(n00b_plan_exec_hot(plan, shard));
    uint64_t expected[] = {1};
    check_set(verified, 4, expected, 1);

    n00b_plan_ordset_t *scanned =
        ordset_ok(n00b_plan_record_scan_hot(shard, nullptr, prefix));
    check_set(scanned, 4, expected, 1);
}

static void
test_overapprox_range_regex_missing_and_path(void)
{
    n00b_store_shard_t *shard = sample_shard(nullptr);

    uint64_t broad_ordinals[] = {1, 2, 3};
    n00b_plan_ordset_t *broad = candidate_set(broad_ordinals, 3);
    n00b_plan_ordset_t *filtered =
        ordset_ok(n00b_plan_record_scan_hot(shard, broad, message_prefix_timeout()));
    uint64_t timeout[] = {1};
    check_set(filtered, 4, timeout, 1);

    n00b_plan_predicate_t *range = predicate_ok(
        n00b_plan_predicate_range(field_target(r"latency_ms"),
                                  json_value(n00b_json_int_new(50)),
                                  json_value(n00b_json_int_new(100))));
    n00b_plan_ordset_t *range_set =
        ordset_ok(n00b_plan_record_scan_hot(shard, nullptr, range));
    check_set(range_set, 4, timeout, 1);

    n00b_regex_t *regex = regex_ok(n00b_regex_new(r"timeout"));
    n00b_plan_predicate_t *regex_pred =
        predicate_ok(n00b_plan_predicate_regex(field_target(r"message"),
                                               regex));
    n00b_plan_ordset_t *regex_set =
        ordset_ok(n00b_plan_record_scan_hot(shard, nullptr, regex_pred));
    check_set(regex_set, 4, timeout, 1);

    n00b_plan_predicate_t *exists =
        predicate_ok(n00b_plan_predicate_exists(field_target(r"level")));
    n00b_plan_ordset_t *exists_set =
        ordset_ok(n00b_plan_record_scan_hot(shard, nullptr, exists));
    uint64_t levels[] = {0, 1, 2};
    check_set(exists_set, 4, levels, 3);

    n00b_plan_predicate_t *missing =
        predicate_ok(n00b_plan_predicate_prefix(field_target(r"unknown"),
                                                r"anything"));
    n00b_plan_ordset_t *missing_set =
        ordset_ok(n00b_plan_record_scan_hot(shard, nullptr, missing));
    check_set(missing_set, 4, nullptr, 0);

    n00b_plan_predicate_t *under =
        predicate_ok(n00b_plan_predicate_under(field_target(r"payload"),
                                               payload_message_path(0)));
    n00b_plan_ordset_t *under_set =
        ordset_ok(n00b_plan_record_scan_hot(shard, nullptr, under));
    check_set(under_set, 4, levels, 3);

    n00b_plan_predicate_t *missing_path =
        predicate_ok(n00b_plan_predicate_under(field_target(r"payload"),
                                               payload_message_path(2)));
    n00b_plan_ordset_t *missing_path_set =
        ordset_ok(n00b_plan_record_scan_hot(shard, nullptr, missing_path));
    check_set(missing_path_set, 4, nullptr, 0);
}

static void
test_in_and_exact_pass_through(void)
{
    n00b_store_shard_t *shard = sample_shard(nullptr);

    n00b_plan_value_list_t *empty = n00b_plan_value_list_new();
    CHECK_ERR(n00b_plan_predicate_in(field_target(r"status"), empty),
              N00B_PLAN_ERR_EMPTY);

    n00b_plan_predicate_t *false_pred =
        predicate_ok(n00b_plan_predicate_false());
    n00b_plan_ordset_t *false_scan =
        ordset_ok(n00b_plan_record_scan_hot(shard, nullptr, false_pred));
    check_set(false_scan, 4, nullptr, 0);

    n00b_plan_node_t *false_plan =
        plan_ok(n00b_plan_build(false_pred, nullptr));
    auto false_kind_r = n00b_plan_node_kind(false_plan);
    CHECK(n00b_result_is_ok(false_kind_r));
    CHECK(n00b_result_get(false_kind_r) == N00B_PLAN_NODE_EMPTY);
    auto false_exact_r = n00b_plan_reads_no_records(false_plan);
    CHECK(n00b_result_is_ok(false_exact_r));
    CHECK(n00b_result_get(false_exact_r));
    check_set(ordset_ok(n00b_plan_exec_hot(false_plan, shard)), 4, nullptr, 0);

    n00b_plan_value_list_t *values = n00b_plan_value_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_value_list_append(values,
                                    json_value(n00b_json_int_new(200)))));
    CHECK(n00b_result_is_ok(
        n00b_plan_value_list_append(values,
                                    json_value(n00b_json_int_new(507)))));
    n00b_plan_predicate_t *in =
        predicate_ok(n00b_plan_predicate_in(field_target(r"status"), values));
    n00b_plan_ordset_t *in_set = ordset_ok(n00b_plan_record_scan_hot(shard, nullptr, in));
    uint64_t expected[] = {0, 2};
    check_set(in_set, 4, expected, 2);

    uint64_t candidates[] = {1, 2};
    n00b_plan_ordset_t *exact = candidate_set(candidates, 2);
    auto pass_r = n00b_plan_record_scan_hot(shard, exact, nullptr);
    CHECK(n00b_result_is_ok(pass_r));
    CHECK(n00b_result_get(pass_r) == exact);
    check_set(n00b_result_get(pass_r), 4, candidates, 2);
}

static void
test_indexed_residual_handoff(void)
{
    n00b_store_index_t     *index = term_index(r"level");
    n00b_store_shard_t     *shard = sample_shard(index);
    n00b_plan_index_list_t *indexes = index_list_with(index);

    n00b_plan_predicate_list_t *children = n00b_plan_predicate_list_new();
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(children, level_eq_error())));
    CHECK(n00b_result_is_ok(
        n00b_plan_predicate_list_append(children, message_prefix_timeout())));
    n00b_plan_predicate_t *and =
        predicate_ok(n00b_plan_predicate_and(children));
    n00b_plan_node_t *plan = plan_ok(n00b_plan_build(and, indexes));

    // The index branch narrows to the error records; the record scan for the
    // prefix then runs only against those.
    auto used_r = n00b_plan_uses_index(plan);
    CHECK(n00b_result_is_ok(used_r));
    CHECK(n00b_result_get(used_r));

    n00b_plan_ordset_t *verified =
        ordset_ok(n00b_plan_exec_hot(plan, shard));
    uint64_t timeout[] = {1};
    check_set(verified, 4, timeout, 1);
}

static void
test_mapped_scan_and_candidate_verification(void)
{
    n00b_store_index_t *index = term_index(r"level");
    n00b_store_shard_t *shard = sample_shard(index);

    auto seal_r = n00b_store_shard_seal(shard,
                                        .seal_ts      = 91,
                                        .base_address = 0x9100u);
    CHECK(n00b_result_is_ok(seal_r));

    auto map_r = n00b_store_map_open_buffer(n00b_result_get(seal_r));
    CHECK(n00b_result_is_ok(map_r));
    n00b_store_map_t *map = n00b_result_get(map_r);

    auto root_r = n00b_store_map_root(map);
    CHECK(n00b_result_is_ok(root_r));
    n00b_store_map_shard_t *root = n00b_result_get(root_r);

    n00b_plan_ordset_t *mapped =
        ordset_ok(n00b_plan_record_scan_mapped(root, nullptr,
                                               message_prefix_timeout()));
    uint64_t timeout[] = {1};
    check_set(mapped, 4, timeout, 1);

    uint64_t broad_ordinals[] = {1, 2, 3};
    n00b_plan_ordset_t *broad = candidate_set(broad_ordinals, 3);
    n00b_plan_predicate_t *range = predicate_ok(
        n00b_plan_predicate_range(field_target(r"latency_ms"),
                                  json_value(n00b_json_int_new(50)),
                                  json_value(n00b_json_int_new(100))));
    n00b_plan_ordset_t *filtered =
        ordset_ok(n00b_plan_record_scan_mapped(root, broad, range));
    check_set(filtered, 4, timeout, 1);

    n00b_plan_node_t *plan = plan_ok(
        n00b_plan_build(level_eq_error(), index_list_with(index)));
    n00b_plan_ordset_t *exact =
        ordset_ok(n00b_plan_exec_mapped(plan, root));
    uint64_t errors[] = {1, 2};
    check_set(exact, 4, errors, 2);

    CHECK(n00b_result_is_ok(n00b_store_map_close(map)));
}


static uint64_t cancel_polls = 0;

static bool
cancel_immediately(void *ctx)
{
    (void)ctx;
    cancel_polls++;
    return true;
}

static bool
never_cancel(void *ctx)
{
    (void)ctx;
    cancel_polls++;
    return false;
}

static void
test_record_scans_are_cancellable(void)
{
    n00b_store_shard_t    *shard  = sample_shard(nullptr);
    n00b_plan_predicate_t *prefix = message_prefix_timeout();

    // A record scan polls the callback as it walks candidates. Returning true
    // aborts the scan and reports it, rather than running to completion.
    cancel_polls = 0;
    CHECK_ERR(n00b_plan_record_scan_hot(shard,
                                        nullptr,
                                        prefix,
                                        .cancel_cb = cancel_immediately),
              N00B_PLAN_ERR_CANCELED);
    CHECK(cancel_polls > 0);

    // The same scan with a callback that declines answers normally, which
    // proves the abort above came from the callback and not from the hook
    // being ignored.
    cancel_polls = 0;
    n00b_plan_ordset_t *finished =
        ordset_ok(n00b_plan_record_scan_hot(shard,
                                            nullptr,
                                            prefix,
                                            .cancel_cb = never_cancel));
    uint64_t expected[] = {1};
    check_set(finished, 4, expected, 1);
    CHECK(cancel_polls > 0);

    // Cancellation reaches record scans through a whole plan, not just the
    // primitive: this predicate has no index, so the plan is a record scan.
    n00b_plan_node_t *plan = plan_ok(n00b_plan_build(prefix, nullptr));
    cancel_polls = 0;
    CHECK_ERR(n00b_plan_exec_hot(plan, shard, .cancel_cb = cancel_immediately),
              N00B_PLAN_ERR_CANCELED);
    CHECK(cancel_polls > 0);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_no_index_plans_a_record_scan();
    test_overapprox_range_regex_missing_and_path();
    test_in_and_exact_pass_through();
    test_indexed_residual_handoff();
    test_mapped_scan_and_candidate_verification();
    test_record_scans_are_cancellable();

    n00b_shutdown();
    return 0;
}
