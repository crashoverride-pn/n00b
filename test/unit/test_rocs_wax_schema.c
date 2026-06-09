/* test/unit/test_rocs_wax_schema.c - WP-013 Phase 1 wax event mapping. */

#include <stdint.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "vfs/backend_memory.h"
#include "vfs/vfs.h"

#include <rocs/n00b_rocs.h>
#include <rocs/wax.h>

#ifndef ROCS_TEST_SOURCE_ROOT
#define ROCS_TEST_SOURCE_ROOT "."
#endif

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

#define CHECK_ERR(expr, expected)                                              \
    do {                                                                       \
        auto _bl_wax_err_r = (expr);                                           \
        CHECK(n00b_result_is_err(_bl_wax_err_r));                              \
        CHECK(n00b_result_get_err(_bl_wax_err_r) == (expected));               \
    } while (0)

static n00b_string_t *
repo_file(n00b_string_t *rel)
{
    return n00b_unicode_str_cat(n00b_string_from_cstr(ROCS_TEST_SOURCE_ROOT),
                                rel);
}

static n00b_string_t *
read_text(n00b_string_t *rel)
{
    auto open_r = n00b_file_open(repo_file(rel), .kind = N00B_FILE_KIND_MMAP);
    CHECK(n00b_result_is_ok(open_r));

    n00b_file_t *file = n00b_result_get(open_r);
    auto         buf_r = n00b_file_as_buffer(file);
    CHECK(n00b_result_is_ok(buf_r));

    n00b_buffer_t *copy = n00b_buffer_copy(n00b_result_get(buf_r));
    n00b_file_close(file);
    return n00b_buffer_to_string(copy);
}

static n00b_string_t *
fixture_line(uint64_t target)
{
    n00b_string_t *text  = read_text(r"/test/unit/data/rocs_wax/events.ndjson");
    uint64_t       index = 0;
    size_t         start = 0;

    for (size_t i = 0; i <= text->u8_bytes; i++) {
        if (i < text->u8_bytes && text->data[i] != '\n') {
            continue;
        }
        if (index == target) {
            return n00b_string_from_raw(text->data + start,
                                        (int64_t)(i - start));
        }
        start = i + 1;
        index++;
    }

    CHECK(false);
    return r"";
}

static n00b_json_node_t *
record_ok(n00b_string_t *line)
{
    auto r = n00b_rocs_wax_record_from_line(line);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_json_node_t *
field(n00b_json_node_t *record, n00b_string_t *name)
{
    n00b_json_node_t *node = n00b_json_object_get(record, name);
    CHECK(node != nullptr);
    return node;
}

static void
check_string_field(n00b_json_node_t *record,
                   n00b_string_t    *name,
                   n00b_string_t    *expected)
{
    n00b_json_node_t *node = field(record, name);
    CHECK(n00b_json_is_string(node));
    CHECK(n00b_unicode_str_eq(n00b_json_as_string(node), expected));
}

static void
check_i64_field(n00b_json_node_t *record,
                n00b_string_t    *name,
                int64_t           expected)
{
    n00b_json_node_t *node = field(record, name);
    CHECK(n00b_json_is_int(node));
    CHECK(n00b_json_as_i64(node) == expected);
}

static n00b_store_schema_t *
schema_ok(void)
{
    auto r = n00b_rocs_wax_schema_new();
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static n00b_store_field_t *
schema_field(n00b_store_schema_t *schema, n00b_string_t *name)
{
    auto field_r = n00b_store_schema_find_field(schema, name);
    CHECK(n00b_result_is_ok(field_r));
    CHECK(n00b_option_is_set(n00b_result_get(field_r)));
    return n00b_option_get(n00b_result_get(field_r));
}

static n00b_vfs_t *
memory_vfs(void)
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
open_wax_store(void)
{
    auto store_r = n00b_store_open_vfs(memory_vfs(), r"/rocs-wax", schema_ok());
    CHECK(n00b_result_is_ok(store_r));
    return n00b_result_get(store_r);
}

static n00b_filter_field_t *
filter_field(n00b_string_t *name)
{
    auto field_r = n00b_filter_field(name);
    CHECK(n00b_result_is_ok(field_r));
    return n00b_result_get(field_r);
}

static n00b_filter_t *
contains_filter(n00b_string_t *field_name, n00b_string_t *term)
{
    auto filter_r = n00b_filter_contains(filter_field(field_name), term);
    CHECK(n00b_result_is_ok(filter_r));
    return n00b_result_get(filter_r);
}

static n00b_filter_t *
exists_filter(n00b_string_t *field_name)
{
    auto filter_r = n00b_filter_exists(filter_field(field_name));
    CHECK(n00b_result_is_ok(filter_r));
    return n00b_result_get(filter_r);
}

static uint64_t
query_count(n00b_store_t *store, n00b_filter_t *filter)
{
    auto query_r = n00b_query_new(filter);
    CHECK(n00b_result_is_ok(query_r));

    auto result_r = n00b_query_run(store, n00b_result_get(query_r));
    CHECK(n00b_result_is_ok(result_r));
    n00b_query_result_t *result = n00b_result_get(result_r);
    uint64_t             count  = n00b_query_count(result);
    CHECK(n00b_result_is_ok(n00b_query_result_close(result)));
    return count;
}

static void
test_public_contracts_and_schema(void)
{
    static_assert((N00B_ROCS_CAPABILITIES & N00B_ROCS_CAP_WAX_DECLS) != 0);
    CHECK(n00b_unicode_str_eq(N00B_ROCS_WAX_NORMALIZED_SCHEMA,
                              r"wax.normalized.v1"));
    CHECK(n00b_unicode_str_eq(n00b_rocs_wax_err_str(N00B_ROCS_WAX_OK),
                              r"OK"));
    CHECK(n00b_rocs_wax_err_str(-9999) != nullptr);

    n00b_store_schema_t *schema = schema_ok();
    auto count_r = n00b_store_schema_get_field_count(schema);
    CHECK(n00b_result_is_ok(count_r));
    CHECK(n00b_result_get(count_r) == 11);

    n00b_store_field_t *search = schema_field(schema, r"search_text");
    auto idx_r = n00b_store_field_get_index_kind(search);
    CHECK(n00b_result_is_ok(idx_r));
    CHECK(n00b_result_get(idx_r) == N00B_STORE_INDEX_FULLTEXT);

    auto include_r = n00b_store_field_include_in_all(search);
    CHECK(n00b_result_is_ok(include_r));
    CHECK(n00b_result_get(include_r));

    n00b_store_field_t *event_id = schema_field(schema, r"event_id");
    idx_r = n00b_store_field_get_index_kind(event_id);
    CHECK(n00b_result_is_ok(idx_r));
    CHECK(n00b_result_get(idx_r) == N00B_STORE_INDEX_TERM);
}

static void
test_fixture_field_mapping(void)
{
    n00b_json_node_t *record = record_ok(fixture_line(0));
    check_string_field(record, r"schema", r"wax.normalized.v1");
    check_string_field(record, r"kind", r"proc.spawn");
    check_string_field(record, r"class", r"proc");
    check_string_field(record, r"family", r"proc");
    check_string_field(record, r"event_id", r"wax:test:proc-spawn:1");
    check_string_field(record, r"policy_revision", r"sha256:default-egress-v1");
    check_string_field(record, r"quality", r"complete");
    check_i64_field(record, r"timestamp", 1777557806000000000);
    check_i64_field(record, r"source_sequence", 1042);

    n00b_json_node_t *raw = field(record, r"raw_json");
    CHECK(n00b_json_is_string(raw));
    CHECK(n00b_unicode_str_contains(n00b_json_as_string(raw), r"proc.spawn"));

    n00b_json_node_t *search = field(record, r"search_text");
    CHECK(n00b_json_is_string(search));
    CHECK(n00b_unicode_str_contains(n00b_json_as_string(search), r"make"));
    CHECK(n00b_unicode_str_contains(n00b_json_as_string(search),
                                    r"fact:mock:proc-exec:1"));
}

static void
test_dotted_lineage_and_derived_fields(void)
{
    n00b_json_node_t *record = record_ok(fixture_line(1));
    check_string_field(record, r"kind", r"file.modify");
    check_string_field(record, r"class", r"file");
    check_string_field(record, r"family", r"fs");
    check_string_field(record, r"event_id", r"mock:file.modify");
    check_string_field(record, r"quality", r"degraded");
    check_i64_field(record, r"source_sequence", 77);

    n00b_json_node_t *search = field(record, r"search_text");
    CHECK(n00b_json_is_string(search));
    CHECK(n00b_unicode_str_contains(n00b_json_as_string(search),
                                    r"metadata-only"));
    CHECK(n00b_unicode_str_contains(n00b_json_as_string(search),
                                    r"/tmp/out.o"));

    record = record_ok(fixture_line(2));
    check_string_field(record, r"class", r"ai");
    check_string_field(record, r"family", r"ai");
    check_string_field(record, r"quality", r"synthetic");
    search = field(record, r"search_text");
    CHECK(n00b_unicode_str_contains(n00b_json_as_string(search), r"codex"));
}

static void
test_invalid_lines(void)
{
    CHECK_ERR(n00b_rocs_wax_record_from_line(nullptr),
              N00B_ROCS_WAX_ERR_ARG);
    CHECK_ERR(n00b_rocs_wax_record_from_line(r"{"),
              N00B_ROCS_WAX_ERR_MALFORMED_JSON);
    CHECK_ERR(n00b_rocs_wax_record_from_line(r"[]"),
              N00B_ROCS_WAX_ERR_NON_OBJECT);
    CHECK_ERR(n00b_rocs_wax_record_from_line(
                  r"{\"schema\":\"wax.raw.v1\",\"kind\":\"raw.local.x\",\"event_id\":\"e\"}"),
              N00B_ROCS_WAX_ERR_UNSUPPORTED_SCHEMA);
    CHECK_ERR(n00b_rocs_wax_record_from_line(
                  r"{\"schema\":\"wax.normalized.v1\",\"event_id\":\"e\"}"),
              N00B_ROCS_WAX_ERR_MISSING_KIND);
    CHECK_ERR(n00b_rocs_wax_record_from_line(
                  r"{\"schema\":\"wax.normalized.v1\",\"kind\":\"proc.spawn\"}"),
              N00B_ROCS_WAX_ERR_MISSING_EVENT_ID);
}

static void
test_public_store_ingest_and_query(void)
{
    n00b_store_t *store = open_wax_store();
    CHECK(query_count(store, exists_filter(r"event_id")) == 0);

    for (uint64_t i = 0; i < 3; i++) {
        auto ingest_r = n00b_store_ingest(store, record_ok(fixture_line(i)));
        CHECK(n00b_result_is_ok(ingest_r));
    }

    CHECK_ERR(n00b_rocs_wax_record_from_line(
                  r"{\"schema\":\"wax.normalized.v1\",\"kind\":\"file.modify\"}"),
              N00B_ROCS_WAX_ERR_MISSING_EVENT_ID);

    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = 99);
    CHECK(n00b_result_is_ok(seal_r));

    CHECK(query_count(store, exists_filter(r"event_id")) == 3);
    CHECK(query_count(store, contains_filter(r"search_text", r"codex")) == 1);
    CHECK(query_count(store, contains_filter(r"search_text", r"metadata")) == 1);
    CHECK(query_count(store, contains_filter(r"search_text", r"missingterm"))
          == 0);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    n00b_printf("test_rocs_wax_schema:");
    test_public_contracts_and_schema();
    test_fixture_field_mapping();
    test_dotted_lineage_and_derived_fields();
    test_invalid_lines();
    test_public_store_ingest_and_query();

    n00b_shutdown();
    return 0;
}
