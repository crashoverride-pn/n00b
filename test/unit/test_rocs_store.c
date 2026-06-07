/* test/unit/test_rocs_store.c - WP-005 Phase 1 store contracts. */

#include <stddef.h>
#include <stdint.h>

#include "n00b.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>
#include <rocs/store.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

static n00b_store_schema_t *
new_schema(void)
{
    auto r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_vfs_t *
new_mounted_vfs(void)
{
    auto vfs_r = n00b_vfs_new();
    CHECK(n00b_result_is_ok(vfs_r));
    n00b_vfs_t *vfs = n00b_result_get(vfs_r);

    auto be_r = n00b_vfs_backend_memory_new();
    CHECK(n00b_result_is_ok(be_r));

    auto mount_r = n00b_vfs_mount(vfs,
                                  r"/",
                                  n00b_result_get(be_r),
                                  0);
    CHECK(n00b_result_is_ok(mount_r));
    return vfs;
}

static n00b_store_t *
open_store(n00b_store_schema_t *schema)
{
    n00b_vfs_t *vfs = new_mounted_vfs();
    auto store_r = n00b_store_open_vfs(vfs, r"/rocs", schema);
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_json_node_t *
record_with(n00b_string_t *field, n00b_json_node_t *value)
{
    n00b_json_node_t *record = n00b_json_object_new();
    n00b_json_object_put_n00b(record, field, value);
    return record;
}

static void
check_route_eq(n00b_store_partition_policy_t *policy,
               n00b_json_node_t              *record,
               n00b_string_t                 *expected)
{
    auto r = n00b_store_partition_route(policy, record);
    CHECK(n00b_result_is_ok(r));
    CHECK(n00b_unicode_str_eq(n00b_result_get(r), expected));
}

static void
test_public_contracts(void)
{
    static_assert((N00B_ROCS_CAPABILITIES & N00B_ROCS_CAP_STORE_DECLS) != 0);
    static_assert(N00B_STORE_OK == 0);
    static_assert(N00B_STORE_ERR_ARG < 0);
    static_assert(N00B_STORE_PARTITION_NONE == 0);
    static_assert(N00B_STORE_RETAIN_NONE == 0);

    CHECK(n00b_store_err_str(N00B_STORE_OK) != nullptr);
    CHECK(n00b_store_err_str(N00B_STORE_ERR_PINNED) != nullptr);
    CHECK(n00b_store_err_str(9999) != nullptr);

    n00b_store_residency_policy_t policy =
        n00b_store_residency_policy_get_default();
    CHECK(policy.preferred_backing == N00B_STORE_IMAGE_AUTO);
    CHECK(policy.allow_direct_mmap);
}

static void
test_schema_field_contracts(void)
{
    n00b_store_schema_t *schema = new_schema();

    auto bad_null = n00b_store_schema_add_field(schema, nullptr);
    CHECK(n00b_result_is_err(bad_null));
    CHECK(n00b_result_get_err(bad_null) == N00B_STORE_ERR_ARG);

    auto bad_empty = n00b_store_schema_add_field(schema, r"");
    CHECK(n00b_result_is_err(bad_empty));
    CHECK(n00b_result_get_err(bad_empty) == N00B_STORE_ERR_ARG);

    auto level_r = n00b_store_schema_add_field(schema,
                                              r"level",
                                              .required = true,
                                              .index_kind = N00B_STORE_INDEX_TERM);
    CHECK(n00b_result_is_ok(level_r));
    n00b_store_field_t *level = n00b_result_get(level_r);

    auto name_r = n00b_store_field_get_name(level);
    CHECK(n00b_result_is_ok(name_r));
    CHECK(n00b_unicode_str_eq(n00b_result_get(name_r), r"level"));

    auto req_r = n00b_store_field_is_required(level);
    CHECK(n00b_result_is_ok(req_r));
    CHECK(n00b_result_get(req_r));

    auto idx_r = n00b_store_field_get_index_kind(level);
    CHECK(n00b_result_is_ok(idx_r));
    CHECK(n00b_result_get(idx_r) == N00B_STORE_INDEX_TERM);

    auto dup_r = n00b_store_schema_add_field(schema, r"level");
    CHECK(n00b_result_is_err(dup_r));
    CHECK(n00b_result_get_err(dup_r) == N00B_STORE_ERR_DUP_FIELD);

    auto count_r = n00b_store_schema_get_field_count(schema);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 1);

    auto found_r = n00b_store_schema_find_field(schema, r"level");
    CHECK(n00b_result_is_ok(found_r));
    CHECK(n00b_option_is_set(n00b_result_get(found_r)));
    CHECK(n00b_option_get(n00b_result_get(found_r)) == level);

    auto miss_r = n00b_store_schema_find_field(schema, r"missing");
    CHECK(n00b_result_is_ok(miss_r));
    CHECK(!n00b_option_is_set(n00b_result_get(miss_r)));

    auto bad_kind = n00b_store_schema_add_field(
        schema,
        r"bad",
        .index_kind = (n00b_store_index_kind_t)999);
    CHECK(n00b_result_is_err(bad_kind));
    CHECK(n00b_result_get_err(bad_kind) == N00B_STORE_ERR_POLICY);
}

static void
test_schema_freeze_and_open_immutability(void)
{
    n00b_store_schema_t *schema = new_schema();
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"ts")));

    auto frozen_r = n00b_store_schema_is_frozen(schema);
    CHECK(n00b_result_is_ok(frozen_r));
    CHECK(!n00b_result_get(frozen_r));

    auto freeze_r = n00b_store_schema_freeze(schema);
    CHECK(n00b_result_is_ok(freeze_r));
    auto freeze_again_r = n00b_store_schema_freeze(schema);
    CHECK(n00b_result_is_ok(freeze_again_r));

    auto add_after_freeze = n00b_store_schema_add_field(schema, r"level");
    CHECK(n00b_result_is_err(add_after_freeze));
    CHECK(n00b_result_get_err(add_after_freeze) == N00B_STORE_ERR_STATE);

    n00b_store_schema_t *open_schema = new_schema();
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(open_schema, r"level")));
    n00b_store_t *store = open_store(open_schema);
    CHECK(store != nullptr);

    auto open_frozen_r = n00b_store_schema_is_frozen(open_schema);
    CHECK(n00b_result_is_ok(open_frozen_r));
    CHECK(n00b_result_get(open_frozen_r));

    auto add_after_open = n00b_store_schema_add_field(open_schema, r"other");
    CHECK(n00b_result_is_err(add_after_open));
    CHECK(n00b_result_get_err(add_after_open) == N00B_STORE_ERR_STATE);
}

static void
test_open_flush_close_state(void)
{
    n00b_store_schema_t *schema = new_schema();
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"level")));

    n00b_vfs_t *vfs = new_mounted_vfs();
    auto bad_vfs = n00b_store_open_vfs(nullptr, r"/rocs", schema);
    CHECK(n00b_result_is_err(bad_vfs));
    CHECK(n00b_result_get_err(bad_vfs) == N00B_STORE_ERR_ARG);

    auto bad_root = n00b_store_open_vfs(vfs, r"relative", schema);
    CHECK(n00b_result_is_err(bad_root));
    CHECK(n00b_result_get_err(bad_root) == N00B_STORE_ERR_ARG);

    auto store_r = n00b_store_open_vfs(vfs, r"/rocs", schema);
    CHECK(n00b_result_is_ok(store_r));
    n00b_store_t *store = n00b_result_get(store_r);

    auto state_r = n00b_store_get_state(store);
    CHECK(n00b_result_is_ok(state_r));
    CHECK(n00b_result_get(state_r) == N00B_STORE_STATE_OPEN);

    auto root_r = n00b_store_get_root(store);
    CHECK(n00b_result_is_ok(root_r));
    CHECK(n00b_unicode_str_eq(n00b_result_get(root_r), r"/rocs"));

    auto schema_r = n00b_store_get_schema(store);
    CHECK(n00b_result_is_ok(schema_r));
    CHECK(n00b_result_get(schema_r) == schema);

    auto flush_r = n00b_store_flush(store);
    CHECK(n00b_result_is_ok(flush_r));

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));

    state_r = n00b_store_get_state(store);
    CHECK(n00b_result_is_ok(state_r));
    CHECK(n00b_result_get(state_r) == N00B_STORE_STATE_CLOSED);

    auto flush_closed = n00b_store_flush(store);
    CHECK(n00b_result_is_err(flush_closed));
    CHECK(n00b_result_get_err(flush_closed) == N00B_STORE_ERR_STATE);

    auto close_closed = n00b_store_close(store);
    CHECK(n00b_result_is_err(close_closed));
    CHECK(n00b_result_get_err(close_closed) == N00B_STORE_ERR_STATE);
}

static void
test_close_with_active_pin(void)
{
    n00b_store_schema_t *schema = new_schema();
    n00b_store_t        *store  = open_store(schema);

    auto pin_r = n00b_store_pin_acquire(store);
    CHECK(n00b_result_is_ok(pin_r));

    auto pins_r = n00b_store_get_active_pins(store);
    CHECK(n00b_result_is_ok(pins_r));
    CHECK(n00b_result_get(pins_r) == 1);

    auto close_pinned = n00b_store_close(store);
    CHECK(n00b_result_is_err(close_pinned));
    CHECK(n00b_result_get_err(close_pinned) == N00B_STORE_ERR_PINNED);

    auto release_r = n00b_store_pin_release(n00b_result_get(pin_r));
    CHECK(n00b_result_is_ok(release_r));

    pins_r = n00b_store_get_active_pins(store);
    CHECK(n00b_result_is_ok(pins_r));
    CHECK(n00b_result_get(pins_r) == 0);

    auto close_r = n00b_store_close(store);
    CHECK(n00b_result_is_ok(close_r));

    auto pin_closed = n00b_store_pin_acquire(store);
    CHECK(n00b_result_is_err(pin_closed));
    CHECK(n00b_result_get_err(pin_closed) == N00B_STORE_ERR_STATE);
}

static void
test_partition_constructors_and_routes(void)
{
    auto none_r = n00b_store_partition_policy_new_none();
    CHECK(n00b_result_is_ok(none_r));
    n00b_store_partition_policy_t *none = n00b_result_get(none_r);

    auto none_kind = n00b_store_partition_policy_get_kind(none);
    CHECK(n00b_result_is_ok(none_kind));
    CHECK(n00b_result_get(none_kind) == N00B_STORE_PARTITION_NONE);
    check_route_eq(none, record_with(r"level", n00b_json_string_new("info")),
                   r"default");

    auto bad_time = n00b_store_partition_policy_new_time(nullptr, 1000);
    CHECK(n00b_result_is_err(bad_time));
    CHECK(n00b_result_get_err(bad_time) == N00B_STORE_ERR_ARG);

    bad_time = n00b_store_partition_policy_new_time(r"ts", 0);
    CHECK(n00b_result_is_err(bad_time));
    CHECK(n00b_result_get_err(bad_time) == N00B_STORE_ERR_ARG);

    auto time_r = n00b_store_partition_policy_new_time(r"ts", 1000);
    CHECK(n00b_result_is_ok(time_r));
    n00b_store_partition_policy_t *time = n00b_result_get(time_r);

    check_route_eq(time, record_with(r"ts", n00b_json_int_new(2500)), r"time/2");
    check_route_eq(time, record_with(r"ts", n00b_json_int_new(-1)), r"default");
    check_route_eq(time, record_with(r"level", n00b_json_string_new("info")),
                   r"default");
    check_route_eq(time, n00b_json_array_new(), r"default");

    auto bad_hash = n00b_store_partition_policy_new_hash(r"level", 0);
    CHECK(n00b_result_is_err(bad_hash));
    CHECK(n00b_result_get_err(bad_hash) == N00B_STORE_ERR_ARG);

    auto hash_r = n00b_store_partition_policy_new_hash(r"level", 16);
    CHECK(n00b_result_is_ok(hash_r));
    n00b_store_partition_policy_t *hash = n00b_result_get(hash_r);

    auto route_a = n00b_store_partition_route(
        hash,
        record_with(r"level", n00b_json_string_new("error")));
    auto route_b = n00b_store_partition_route(
        hash,
        record_with(r"level", n00b_json_string_new("error")));
    CHECK(n00b_result_is_ok(route_a));
    CHECK(n00b_result_is_ok(route_b));
    CHECK(n00b_unicode_str_eq(n00b_result_get(route_a), n00b_result_get(route_b)));
    CHECK(n00b_unicode_str_starts_with(n00b_result_get(route_a), r"hash/"));

    check_route_eq(hash, record_with(r"level", n00b_json_array_new()), r"default");
}

static void
test_policy_constructors(void)
{
    auto retain_none = n00b_store_retain_policy_new(N00B_STORE_RETAIN_NONE);
    CHECK(n00b_result_is_ok(retain_none));
    auto retain_inline = n00b_store_retain_policy_new(N00B_STORE_RETAIN_INLINE);
    CHECK(n00b_result_is_ok(retain_inline));
    auto retain_external =
        n00b_store_retain_policy_new(N00B_STORE_RETAIN_EXTERNAL);
    CHECK(n00b_result_is_ok(retain_external));

    auto bad_retain =
        n00b_store_retain_policy_new((n00b_store_retain_kind_t)999);
    CHECK(n00b_result_is_err(bad_retain));
    CHECK(n00b_result_get_err(bad_retain) == N00B_STORE_ERR_POLICY);

    auto manual_seal = n00b_store_seal_policy_new();
    CHECK(n00b_result_is_ok(manual_seal));
    auto threshold_seal = n00b_store_seal_policy_new(.max_records = 1024,
                                                     .max_bytes = 1 << 20);
    CHECK(n00b_result_is_ok(threshold_seal));
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_public_contracts();
    test_schema_field_contracts();
    test_schema_freeze_and_open_immutability();
    test_open_flush_close_state();
    test_close_with_active_pin();
    test_partition_constructors_and_routes();
    test_policy_constructors();

    n00b_shutdown();
    return 0;
}
