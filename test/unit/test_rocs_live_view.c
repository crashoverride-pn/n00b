/* test/unit/test_rocs_live_view.c - WP-009 Phase 1 live view entry. */

#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/query.h>

#ifdef N00B_ROCS_INTERNAL_QUERY_H
#error "rocs/query.h must not include internal query declarations"
#endif

#include <rocs/n00b_rocs.h>
#include "internal/rocs/query.h"
#include "internal/rocs/store.h"

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

#define CHECK_CODE_ERR(expr, expected)                                         \
    do {                                                                       \
        auto _bl_query_err_result = (expr);                                    \
        CHECK(n00b_result_is_err(_bl_query_err_result));                       \
        CHECK(n00b_result_get_err(_bl_query_err_result) == (expected));        \
    } while (0)

typedef struct {
    n00b_store_t               *store;
    n00b_filter_t              *filter;
    n00b_store_catalog_entry_t *first;
    n00b_store_catalog_entry_t *second;
    n00b_store_catalog_entry_t *third;
    n00b_store_pos_t            first_pos;
    n00b_store_pos_t            second_pos;
    n00b_store_pos_t            third_pos;
} live_sample_t;

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
open_store(void)
{
    auto store_r = n00b_store_open_vfs(new_memory_vfs(),
                                       r"/rocs-live-view",
                                       new_schema());
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_json_node_t *
record_with_id(int64_t id)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, r"id", n00b_json_int_new(id));
    return record;
}

static n00b_store_catalog_entry_t *
ingest_and_seal(n00b_store_t *store, int64_t id, uint64_t seal_ts)
{
    auto ingest_r = n00b_store_ingest(store, record_with_id(id));
    CHECK(n00b_result_is_ok(ingest_r));

    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = seal_ts);
    CHECK(n00b_result_is_ok(seal_r));
    return n00b_result_get(seal_r);
}

static n00b_filter_t *
query_filter(void)
{
    auto field_r = n00b_filter_field(r"id");
    CHECK(n00b_result_is_ok(field_r));

    auto filter_r = n00b_filter_exists(n00b_result_get(field_r));
    CHECK(n00b_result_is_ok(filter_r));
    return n00b_result_get(filter_r);
}

static n00b_store_pos_t
entry_pos(n00b_store_catalog_entry_t *entry, uint64_t ordinal)
{
    auto id_r  = n00b_store_catalog_entry_get_shard_id(entry);
    auto gen_r = n00b_store_catalog_entry_get_generation(entry);
    CHECK(n00b_result_is_ok(id_r));
    CHECK(n00b_result_is_ok(gen_r));
    return (n00b_store_pos_t){
        .shard_id   = n00b_result_get(id_r),
        .ordinal    = ordinal,
        .generation = n00b_result_get(gen_r),
    };
}

static live_sample_t
new_live_sample(void)
{
    live_sample_t sample = {};
    sample.store  = open_store();
    sample.filter = query_filter();
    sample.first  = ingest_and_seal(sample.store, 1, 701);
    sample.second = ingest_and_seal(sample.store, 2, 702);
    sample.third  = ingest_and_seal(sample.store, 3, 703);
    sample.first_pos  = entry_pos(sample.first, 0);
    sample.second_pos = entry_pos(sample.second, 0);
    sample.third_pos  = entry_pos(sample.third, 0);
    return sample;
}

static uint64_t
active_pins(n00b_store_t *store)
{
    auto pins_r = n00b_store_get_active_pins(store);
    CHECK(n00b_result_is_ok(pins_r));
    return n00b_result_get(pins_r);
}

static n00b_query_view_t *
view_ok(n00b_result_t(n00b_query_view_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_query_view_t *view = n00b_result_get(r);
    CHECK(view != nullptr);
    return view;
}

static void
close_view_true(n00b_query_view_t *view)
{
    auto close_r = n00b_query_view_close(view);
    CHECK(n00b_result_is_ok(close_r));
    CHECK(n00b_result_get(close_r));
}

static void
close_cursor_true(n00b_query_cursor_t *cursor)
{
    auto close_r = n00b_query_cursor_close(cursor);
    CHECK(n00b_result_is_ok(close_r));
    CHECK(n00b_result_get(close_r));
}

static n00b_query_cursor_t *
cursor_ok(n00b_result_t(n00b_query_cursor_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_query_cursor_t *cursor = n00b_result_get(r);
    CHECK(cursor != nullptr);
    return cursor;
}

static uint64_t
boundary_count(n00b_query_view_t *view)
{
    auto count_r = n00b_query_view_boundary_count(view);
    CHECK(n00b_result_is_ok(count_r));
    return n00b_result_get(count_r);
}

static n00b_query_boundary_entry_t
boundary_entry(n00b_query_view_t *view, uint64_t index)
{
    auto entry_r = n00b_query_view_boundary_entry_at(view, index);
    CHECK(n00b_result_is_ok(entry_r));
    CHECK(n00b_option_is_set(n00b_result_get(entry_r)));
    return n00b_option_get(n00b_result_get(entry_r));
}

static void
check_owned_boundary_entry(n00b_query_boundary_entry_t boundary,
                           n00b_store_catalog_entry_t *entry)
{
    auto id_r     = n00b_store_catalog_entry_get_shard_id(entry);
    auto gen_r    = n00b_store_catalog_entry_get_generation(entry);
    auto path_r   = n00b_store_catalog_entry_get_object_path(entry);
    auto part_r   = n00b_store_catalog_entry_get_partition_key(entry);
    auto record_r = n00b_store_catalog_entry_get_record_count(entry);
    CHECK(n00b_result_is_ok(id_r));
    CHECK(n00b_result_is_ok(gen_r));
    CHECK(n00b_result_is_ok(path_r));
    CHECK(n00b_result_is_ok(part_r));
    CHECK(n00b_result_is_ok(record_r));

    CHECK(boundary.shard_id == n00b_result_get(id_r));
    CHECK(boundary.generation == n00b_result_get(gen_r));
    CHECK(boundary.record_count == n00b_result_get(record_r));
    CHECK(n00b_unicode_str_eq(boundary.object_path, n00b_result_get(path_r)));
    CHECK(n00b_unicode_str_eq(boundary.partition_key, n00b_result_get(part_r)));
    CHECK(boundary.object_path != n00b_result_get(path_r));
    CHECK(boundary.partition_key != n00b_result_get(part_r));
}

static void
check_position(n00b_store_pos_t actual, n00b_store_pos_t expected)
{
    CHECK(n00b_store_pos_compare(actual, expected) == 0);
}

static void
check_position_option(n00b_result_t(n00b_option_t(n00b_store_pos_t)) r,
                      n00b_store_pos_t                               expected)
{
    CHECK(n00b_result_is_ok(r));
    n00b_option_t(n00b_store_pos_t) opt = n00b_result_get(r);
    CHECK(n00b_option_is_set(opt));
    check_position(n00b_option_get(opt), expected);
}

static void
check_none_option(n00b_result_t(n00b_option_t(n00b_store_pos_t)) r)
{
    CHECK(n00b_result_is_ok(r));
    CHECK(!n00b_option_is_set(n00b_result_get(r)));
}

static void
expect_retention_payload(n00b_result_t(n00b_query_view_t *) r,
                         n00b_store_pos_t                   requested,
                         n00b_store_pos_t                   oldest)
{
    CHECK(n00b_result_is_err(r));
    n00b_result_error_t carrier = n00b_result_get_error(r);
    CHECK(carrier.kind == N00B_RESULT_ERROR_PAYLOAD);
    CHECK(carrier.payload_type == typehash(n00b_query_retention_error_t *));
    CHECK(carrier.payload != nullptr);
    CHECK(n00b_result_is_err_payload(n00b_query_retention_error_t *, r));

    n00b_query_retention_error_t *payload =
        n00b_result_get_err_payload(n00b_query_retention_error_t *, r);

    auto code_r = n00b_query_retention_error_code(payload);
    CHECK(n00b_result_is_ok(code_r));
    CHECK(n00b_result_get(code_r) == N00B_QUERY_ERR_RETENTION);

    auto boundary_r = n00b_query_retention_error_boundary(payload);
    CHECK(n00b_result_is_ok(boundary_r));
    CHECK(n00b_result_get(boundary_r) == N00B_QUERY_BOUNDARY_RESUME);

    auto requested_r = n00b_query_retention_error_requested(payload);
    CHECK(n00b_result_is_ok(requested_r));
    check_position(n00b_result_get(requested_r), requested);

    auto oldest_r = n00b_query_retention_error_oldest_available(payload);
    CHECK(n00b_result_is_ok(oldest_r));
    CHECK(n00b_option_is_set(n00b_result_get(oldest_r)));
    check_position(n00b_option_get(n00b_result_get(oldest_r)), oldest);
}

static void
test_live_view_captures_boundary_and_cutover_state(void)
{
    live_sample_t sample = new_live_sample();

    n00b_query_view_t *snapshot = view_ok(n00b_query_view(sample.store,
                                                          sample.filter));
    check_position_option(n00b_query_view_snapshot_upper_bound(snapshot),
                          sample.third_pos);
    check_none_option(n00b_query_view_live_start_after(snapshot));
    close_view_true(snapshot);

    n00b_query_view_t *live = view_ok(n00b_query_view(
        sample.store,
        sample.filter,
        .mode = N00B_QUERY_MODE_LIVE,
        .limit = 9));
    CHECK(active_pins(sample.store) == 1);
    CHECK(n00b_result_get(n00b_query_view_mode(live))
          == N00B_QUERY_MODE_LIVE);
    CHECK(n00b_result_get(n00b_query_view_limit(live)) == 9);
    CHECK(boundary_count(live) == 3);
    check_position_option(n00b_query_view_snapshot_upper_bound(live),
                          sample.third_pos);
    check_none_option(n00b_query_view_live_start_after(live));
    check_position_option(n00b_query_view_live_historical_upper_bound(live),
                          sample.third_pos);
    check_position_option(n00b_query_view_live_cutover_after(live),
                          sample.third_pos);

    ingest_and_seal(sample.store, 4, 704);
    CHECK(boundary_count(live) == 3);
    check_position_option(n00b_query_view_snapshot_upper_bound(live),
                          sample.third_pos);
    check_position_option(n00b_query_view_live_cutover_after(live),
                          sample.third_pos);

    close_cursor_true(cursor_ok(n00b_query_cursor(live)));
    CHECK(active_pins(sample.store) == 1);

    close_view_true(live);
    CHECK(active_pins(sample.store) == 0);
    auto close_again_r = n00b_query_view_close(live);
    CHECK(n00b_result_is_ok(close_again_r));
    CHECK(!n00b_result_get(close_again_r));
    CHECK(active_pins(sample.store) == 0);
}

static void
test_live_as_of_rejected_before_store_pin(void)
{
    live_sample_t sample = new_live_sample();
    CHECK(active_pins(sample.store) == 0);

    CHECK_CODE_ERR(n00b_query_view(sample.store,
                                   sample.filter,
                                   .mode = N00B_QUERY_MODE_LIVE,
                                   .as_of = &sample.second_pos),
                   N00B_QUERY_ERR_INVALID_OPTION);
    CHECK(active_pins(sample.store) == 0);
}

static void
test_live_resume_start_and_cutover_state(void)
{
    live_sample_t sample = new_live_sample();
    n00b_store_pos_t resume = sample.second_pos;

    n00b_query_view_t *live = view_ok(n00b_query_view(
        sample.store,
        sample.filter,
        .mode = N00B_QUERY_MODE_LIVE,
        .resume = &resume));
    CHECK(boundary_count(live) == 2);
    check_position_option(n00b_query_view_live_start_after(live), resume);
    check_position_option(n00b_query_view_live_historical_upper_bound(live),
                          sample.third_pos);
    check_position_option(n00b_query_view_live_cutover_after(live),
                          sample.third_pos);
    close_cursor_true(cursor_ok(n00b_query_cursor(live)));
    close_view_true(live);
    CHECK(active_pins(sample.store) == 0);
}

static void
test_live_boundary_uses_stable_store_snapshot_copy(void)
{
    live_sample_t sample = new_live_sample();

    auto guard_r =
        n00b_store_catalog_test_set_borrowed_enumeration_disabled(
            sample.store,
            true);
    CHECK(n00b_result_is_ok(guard_r));

    n00b_query_view_t *live = view_ok(n00b_query_view(
        sample.store,
        sample.filter,
        .mode = N00B_QUERY_MODE_LIVE));
    CHECK(boundary_count(live) == 3);
    check_owned_boundary_entry(boundary_entry(live, 0), sample.first);
    check_owned_boundary_entry(boundary_entry(live, 2), sample.third);
    check_position_option(n00b_query_view_snapshot_upper_bound(live),
                          sample.third_pos);
    check_position_option(n00b_query_view_live_historical_upper_bound(live),
                          sample.third_pos);
    check_position_option(n00b_query_view_live_cutover_after(live),
                          sample.third_pos);
    close_view_true(live);

    auto unguard_r =
        n00b_store_catalog_test_set_borrowed_enumeration_disabled(
            sample.store,
            false);
    CHECK(n00b_result_is_ok(unguard_r));
    CHECK(active_pins(sample.store) == 0);
}

static void
test_live_resume_retention_payloads_preserve_carrier(void)
{
    live_sample_t sample = new_live_sample();

    n00b_store_pos_t invalid_ordinal = sample.first_pos;
    invalid_ordinal.ordinal = 99;
    expect_retention_payload(n00b_query_view(sample.store,
                                             sample.filter,
                                             .mode = N00B_QUERY_MODE_LIVE,
                                             .resume = &invalid_ordinal),
                             invalid_ordinal,
                             sample.first_pos);
    CHECK(active_pins(sample.store) == 0);

    n00b_store_pos_t missing = {
        .generation = sample.first_pos.generation,
        .shard_id   = 999,
        .ordinal    = 0,
    };
    expect_retention_payload(n00b_query_view(sample.store,
                                             sample.filter,
                                             .mode = N00B_QUERY_MODE_LIVE,
                                             .resume = &missing),
                             missing,
                             sample.first_pos);
    CHECK(active_pins(sample.store) == 0);

    n00b_store_pos_t stale_generation = sample.first_pos;
    stale_generation.generation++;
    expect_retention_payload(n00b_query_view(sample.store,
                                             sample.filter,
                                             .mode = N00B_QUERY_MODE_LIVE,
                                             .resume = &stale_generation),
                             stale_generation,
                             sample.first_pos);
    CHECK(active_pins(sample.store) == 0);

    auto drop_r = n00b_store_drop_sealed_shard(sample.store,
                                               sample.first_pos.shard_id);
    CHECK(n00b_result_is_ok(drop_r));
    expect_retention_payload(n00b_query_view(sample.store,
                                             sample.filter,
                                             .mode = N00B_QUERY_MODE_LIVE,
                                             .resume = &sample.first_pos),
                             sample.first_pos,
                             sample.second_pos);
    CHECK(active_pins(sample.store) == 0);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_live_view_captures_boundary_and_cutover_state();
    test_live_as_of_rejected_before_store_pin();
    test_live_resume_start_and_cutover_state();
    test_live_boundary_uses_stable_store_snapshot_copy();
    test_live_resume_retention_payloads_preserve_carrier();

    n00b_shutdown();
    return 0;
}
