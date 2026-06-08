/* test/unit/test_rocs_query_view.c - WP-008 Phase 1 query view shell. */

#include <stdint.h>

#include "n00b.h"
#include "conduit/conduit.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/query.h>

#ifdef N00B_ROCS_INTERNAL_QUERY_H
#error "rocs/query.h must not include internal query declarations"
#endif

#ifdef N00B_ROCS_INTERNAL_PLAN_H
#error "rocs/query.h must not include internal planner declarations"
#endif

#include <rocs/n00b_rocs.h>

#ifndef N00B_ROCS_CAP_QUERY_DECLS
#error "rocs/n00b_rocs.h must expose the query capability bit"
#endif

#ifdef N00B_ROCS_INTERNAL_QUERY_H
#error "rocs/n00b_rocs.h must not include internal query declarations"
#endif

#ifdef N00B_ROCS_INTERNAL_PLAN_H
#error "rocs/n00b_rocs.h must not include internal planner declarations"
#endif

#include "internal/rocs/query.h"

#ifdef N00B_ROCS_INTERNAL_PLAN_H
#error "internal query inspectors must not include planner declarations"
#endif

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
open_store(n00b_vfs_t *vfs)
{
    auto store_r = n00b_store_open_vfs(vfs, r"/rocs", new_schema());
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

static n00b_query_view_t *
view_ok(n00b_result_t(n00b_query_view_t *) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_query_view_t *view = n00b_result_get(r);
    CHECK(view != nullptr);
    return view;
}

static uint64_t
active_pins(n00b_store_t *store)
{
    auto pins_r = n00b_store_get_active_pins(store);
    CHECK(n00b_result_is_ok(pins_r));
    return n00b_result_get(pins_r);
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

static void
check_entry_matches(n00b_query_boundary_entry_t  boundary,
                    n00b_store_catalog_entry_t  *entry,
                    uint64_t                     seal_ts)
{
    auto id_r      = n00b_store_catalog_entry_get_shard_id(entry);
    auto gen_r     = n00b_store_catalog_entry_get_generation(entry);
    auto schema_r  = n00b_store_catalog_entry_get_schema_generation(entry);
    auto records_r = n00b_store_catalog_entry_get_record_count(entry);
    auto path_r    = n00b_store_catalog_entry_get_object_path(entry);
    auto bytes_r   = n00b_store_catalog_entry_get_byte_len(entry);
    auto part_r    = n00b_store_catalog_entry_get_partition_key(entry);
    CHECK(n00b_result_is_ok(id_r));
    CHECK(n00b_result_is_ok(gen_r));
    CHECK(n00b_result_is_ok(schema_r));
    CHECK(n00b_result_is_ok(records_r));
    CHECK(n00b_result_is_ok(path_r));
    CHECK(n00b_result_is_ok(bytes_r));
    CHECK(n00b_result_is_ok(part_r));

    CHECK(boundary.shard_id == n00b_result_get(id_r));
    CHECK(boundary.generation == n00b_result_get(gen_r));
    CHECK(boundary.schema_generation == n00b_result_get(schema_r));
    CHECK(boundary.record_count == n00b_result_get(records_r));
    CHECK(boundary.seal_ts == seal_ts);
    CHECK(boundary.byte_len == n00b_result_get(bytes_r));
    CHECK(n00b_unicode_str_eq(boundary.object_path, n00b_result_get(path_r)));
    CHECK(n00b_unicode_str_eq(boundary.partition_key, n00b_result_get(part_r)));
    CHECK(boundary.object_path != n00b_result_get(path_r));
    CHECK(boundary.partition_key != n00b_result_get(part_r));
    CHECK(!n00b_option_is_set(boundary.etag));
}

static void
close_true(n00b_query_view_t *view)
{
    auto close_r = n00b_query_view_close(view);
    CHECK(n00b_result_is_ok(close_r));
    CHECK(n00b_result_get(close_r));
}

static void
test_snapshot_boundary_later_commit_and_pin_lifetime(void)
{
    n00b_store_t *store = open_store(new_memory_vfs());
    n00b_store_catalog_entry_t *first  = ingest_and_seal(store, 1, 101);
    n00b_store_catalog_entry_t *second = ingest_and_seal(store, 2, 102);
    CHECK(active_pins(store) == 0);

    n00b_query_view_t *view = view_ok(n00b_query_view(store,
                                                      query_filter(),
                                                      .limit = 7));
    CHECK(active_pins(store) == 1);
    CHECK(boundary_count(view) == 2);
    CHECK(n00b_result_get(n00b_query_view_limit(view)) == 7);
    check_entry_matches(boundary_entry(view, 0), first, 101);
    check_entry_matches(boundary_entry(view, 1), second, 102);

    ingest_and_seal(store, 3, 103);
    CHECK(boundary_count(view) == 2);

    auto close_block_r = n00b_store_close(store);
    CHECK(n00b_result_is_err(close_block_r));
    CHECK(n00b_result_get_err(close_block_r) == N00B_STORE_ERR_PINNED);

    close_true(view);
    CHECK(active_pins(store) == 0);
    CHECK(n00b_result_get(n00b_query_view_is_closed(view)));

    auto close_again_r = n00b_query_view_close(view);
    CHECK(n00b_result_is_ok(close_again_r));
    CHECK(!n00b_result_get(close_again_r));
    CHECK(active_pins(store) == 0);
}

static void
test_live_and_out_rejected_without_view(void)
{
    n00b_store_t  *store  = open_store(new_memory_vfs());
    n00b_filter_t *filter = query_filter();

    CHECK_CODE_ERR(n00b_query_view(store,
                                   filter,
                                   .mode = N00B_QUERY_MODE_LIVE),
                   N00B_QUERY_ERR_UNSUPPORTED_MODE);
    CHECK(active_pins(store) == 0);

    auto conduit_r = n00b_conduit_new();
    CHECK(n00b_result_is_ok(conduit_r));
    n00b_conduit_t *conduit = n00b_result_get(conduit_r);
    CHECK_CODE_ERR(n00b_query_view(store, filter, .out = conduit),
                   N00B_QUERY_ERR_UNSUPPORTED_MODE);
    CHECK(active_pins(store) == 0);
    n00b_conduit_destroy(conduit);
}

static void
test_null_and_invalid_input_validation(void)
{
    n00b_store_t  *store  = open_store(new_memory_vfs());
    n00b_filter_t *filter = query_filter();

    CHECK_CODE_ERR(n00b_query_view(nullptr, filter), N00B_QUERY_ERR_ARG);
    CHECK_CODE_ERR(n00b_query_view(store, nullptr), N00B_QUERY_ERR_ARG);
    CHECK_CODE_ERR(n00b_query_view(store,
                                   filter,
                                   .mode = (n00b_query_mode_t)99),
                   N00B_QUERY_ERR_ARG);
    CHECK_CODE_ERR(n00b_query_view_close(nullptr), N00B_QUERY_ERR_ARG);
    CHECK(active_pins(store) == 0);
}

static void
expect_retention_payload(n00b_result_t(n00b_query_view_t *) r,
                         n00b_query_boundary_kind_t         boundary,
                         n00b_store_pos_t                   requested,
                         uint64_t                           oldest_shard)
{
    CHECK(n00b_result_is_err_payload(n00b_query_retention_error_t *, r));
    n00b_query_retention_error_t *payload =
        n00b_result_get_err_payload(n00b_query_retention_error_t *, r);

    auto code_r = n00b_query_retention_error_code(payload);
    CHECK(n00b_result_is_ok(code_r));
    CHECK(n00b_result_get(code_r) == N00B_QUERY_ERR_RETENTION);

    auto boundary_r = n00b_query_retention_error_boundary(payload);
    CHECK(n00b_result_is_ok(boundary_r));
    CHECK(n00b_result_get(boundary_r) == boundary);

    auto requested_r = n00b_query_retention_error_requested(payload);
    CHECK(n00b_result_is_ok(requested_r));
    CHECK(n00b_store_pos_compare(n00b_result_get(requested_r),
                                 requested) == 0);

    auto oldest_r = n00b_query_retention_error_oldest_available(payload);
    CHECK(n00b_result_is_ok(oldest_r));
    CHECK(n00b_option_is_set(n00b_result_get(oldest_r)));
    CHECK(n00b_option_get(n00b_result_get(oldest_r)).shard_id
          == oldest_shard);
}

static void
test_resume_and_as_of_validation(void)
{
    n00b_store_t *store = open_store(new_memory_vfs());
    n00b_store_catalog_entry_t *first  = ingest_and_seal(store, 1, 201);
    n00b_store_catalog_entry_t *second = ingest_and_seal(store, 2, 202);
    n00b_store_catalog_entry_t *third  = ingest_and_seal(store, 3, 203);
    n00b_filter_t *filter = query_filter();

    n00b_store_pos_t resume = entry_pos(second, 0);
    n00b_store_pos_t as_of  = entry_pos(third, 0);
    n00b_query_view_t *view = view_ok(n00b_query_view(store,
                                                      filter,
                                                      .resume = &resume,
                                                      .as_of = &as_of));
    CHECK(boundary_count(view) == 2);
    CHECK(boundary_entry(view, 0).shard_id == resume.shard_id);
    CHECK(boundary_entry(view, 1).shard_id == as_of.shard_id);

    auto resume_r = n00b_query_view_resume(view);
    auto as_of_r  = n00b_query_view_as_of(view);
    CHECK(n00b_result_is_ok(resume_r));
    CHECK(n00b_result_is_ok(as_of_r));
    CHECK(n00b_store_pos_compare(n00b_option_get(n00b_result_get(resume_r)),
                                 resume) == 0);
    CHECK(n00b_store_pos_compare(n00b_option_get(n00b_result_get(as_of_r)),
                                 as_of) == 0);
    close_true(view);

    n00b_store_pos_t empty_resume = entry_pos(third, 0);
    n00b_store_pos_t empty_as_of  = entry_pos(second, 0);
    n00b_query_view_t *empty = view_ok(n00b_query_view(store,
                                                       filter,
                                                       .resume = &empty_resume,
                                                       .as_of = &empty_as_of));
    CHECK(boundary_count(empty) == 0);
    close_true(empty);

    n00b_store_pos_t bad_as_of = entry_pos(first, 99);
    expect_retention_payload(n00b_query_view(store,
                                             filter,
                                             .as_of = &bad_as_of),
                             N00B_QUERY_BOUNDARY_AS_OF,
                             bad_as_of,
                             entry_pos(first, 0).shard_id);
    CHECK(active_pins(store) == 0);

    n00b_store_pos_t missing_resume = {
        .generation = resume.generation,
        .shard_id   = 999,
        .ordinal    = 0,
    };
    expect_retention_payload(n00b_query_view(store,
                                             filter,
                                             .resume = &missing_resume),
                             N00B_QUERY_BOUNDARY_RESUME,
                             missing_resume,
                             entry_pos(first, 0).shard_id);
    CHECK(active_pins(store) == 0);
}

static void
test_retained_away_boundary_payload(void)
{
    n00b_store_t *store = open_store(new_memory_vfs());
    n00b_store_catalog_entry_t *first  = ingest_and_seal(store, 1, 301);
    n00b_store_catalog_entry_t *second = ingest_and_seal(store, 2, 302);
    ingest_and_seal(store, 3, 303);

    n00b_store_pos_t stale = entry_pos(first, 0);
    n00b_store_pos_t first_pos = entry_pos(first, 0);
    auto drop_r = n00b_store_drop_sealed_shard(store, first_pos.shard_id);
    CHECK(n00b_result_is_ok(drop_r));

    expect_retention_payload(n00b_query_view(store,
                                             query_filter(),
                                             .resume = &stale),
                             N00B_QUERY_BOUNDARY_RESUME,
                             stale,
                             entry_pos(second, 0).shard_id);
    CHECK(active_pins(store) == 0);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};
    n00b_init(&runtime, argc, argv);

    test_snapshot_boundary_later_commit_and_pin_lifetime();
    test_live_and_out_rejected_without_view();
    test_null_and_invalid_input_validation();
    test_resume_and_as_of_validation();
    test_retained_away_boundary_payload();

    n00b_shutdown();
    return 0;
}
