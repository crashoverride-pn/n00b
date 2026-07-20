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

static bool
schema_has_field(n00b_store_schema_t *schema, n00b_string_t *name)
{
    auto field_r = n00b_store_schema_find_field(schema, name);
    CHECK(n00b_result_is_ok(field_r));
    return n00b_option_is_set(n00b_result_get(field_r));
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

// Unqualified (catch-all) contains filter: resolves to the reserved
// __n00b_search_text full-text column via n00b_filter_any().
static n00b_filter_t *
any_contains(n00b_string_t *term)
{
    auto filter_r = n00b_filter_contains(n00b_filter_any(), term);
    CHECK(n00b_result_is_ok(filter_r));
    return n00b_result_get(filter_r);
}

static n00b_filter_t *
eq_filter(n00b_string_t *field_name, n00b_filter_value_t value)
{
    auto filter_r = n00b_filter_eq(filter_field(field_name), value);
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
    // 10 individually-added fields + 58 sparse-exact fields. Grew from 64 to 68
    // with the AI session-bind columns (ai/body .ai_start_id + .ai_session_uuid).
    CHECK(n00b_result_get(count_r) == 68);

    // The reserved full-text catch-all column is index-only and is NOT a
    // user-addressable schema field.
    CHECK(!schema_has_field(schema, r"search_text"));
    CHECK(!schema_has_field(schema, r"__n00b_search_text"));

    n00b_store_field_t *event_id = schema_field(schema, r"event_id");
    auto idx_r = n00b_store_field_get_index_kind(event_id);
    CHECK(n00b_result_is_ok(idx_r));
    CHECK(n00b_result_get(idx_r) == N00B_STORE_INDEX_TERM);

    auto postings_r = n00b_store_field_get_postings_kind(event_id);
    CHECK(n00b_result_is_ok(postings_r));
    CHECK(n00b_result_get(postings_r) == N00B_STORE_POSTINGS_SPARSE);

    n00b_store_field_t *body_pid = schema_field(schema, r"body.pid");
    idx_r = n00b_store_field_get_index_kind(body_pid);
    CHECK(n00b_result_is_ok(idx_r));
    CHECK(n00b_result_get(idx_r) == N00B_STORE_INDEX_TERM);

    postings_r = n00b_store_field_get_postings_kind(body_pid);
    CHECK(n00b_result_is_ok(postings_r));
    CHECK(n00b_result_get(postings_r) == N00B_STORE_POSTINGS_SPARSE);

    n00b_store_field_t *chalk_id = schema_field(schema, r"body.chalk_id");
    idx_r = n00b_store_field_get_index_kind(chalk_id);
    CHECK(n00b_result_is_ok(idx_r));
    CHECK(n00b_result_get(idx_r) == N00B_STORE_INDEX_TERM);

    n00b_store_field_t *kind = schema_field(schema, r"kind");
    postings_r = n00b_store_field_get_postings_kind(kind);
    CHECK(n00b_result_is_ok(postings_r));
    CHECK(n00b_result_get(postings_r) == N00B_STORE_POSTINGS_DENSE);

    n00b_store_field_t *pid = schema_field(schema, r"process.pid");
    idx_r = n00b_store_field_get_index_kind(pid);
    CHECK(n00b_result_is_ok(idx_r));
    CHECK(n00b_result_get(idx_r) == N00B_STORE_INDEX_TERM);

    postings_r = n00b_store_field_get_postings_kind(pid);
    CHECK(n00b_result_is_ok(postings_r));
    CHECK(n00b_result_get(postings_r) == N00B_STORE_POSTINGS_SPARSE);

    CHECK(!schema_has_field(schema, r"quality.state"));
    CHECK(!schema_has_field(schema, r"policy.revision"));
}

static void
test_fixture_field_mapping(void)
{
    n00b_json_node_t *record = record_ok(fixture_line(0));
    check_string_field(record, r"schema", r"wax.normalized.v1");
    check_string_field(record, r"kind", r"proc.spawn");
    check_string_field(record, r"class", r"proc");
    check_string_field(record, r"event_id", r"wax:test:proc-spawn:1");
    check_i64_field(record, r"ts_ns", 1777557806000000000);

    CHECK(n00b_json_object_get(record, r"raw_json") == nullptr);

    // search_text is an index-only catch-all column; it is never materialized
    // into the record body.
    CHECK(n00b_json_object_get(record, r"search_text") == nullptr);
}

static void
test_dotted_lineage_and_derived_fields(void)
{
    n00b_json_node_t *record = record_ok(fixture_line(1));
    check_string_field(record, r"kind", r"file.modify");
    check_string_field(record, r"class", r"file");
    check_string_field(record, r"lineage.event_id", r"mock:file.modify");

    // search_text is index-only; not present in the record body.
    CHECK(n00b_json_object_get(record, r"search_text") == nullptr);

    record = record_ok(fixture_line(2));
    check_string_field(record, r"kind", r"ai.session_start");
    check_string_field(record, r"event_id", r"wax:test:ai-session-start:1");
    CHECK(n00b_json_object_get(record, r"search_text") == nullptr);
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
test_live_body_shape_indexes(void)
{
    n00b_store_t *store = open_wax_store();

    n00b_json_node_t *proc = record_ok(
        r"{\"schema\":\"wax.normalized.v1\",\"kind\":\"proc.spawn\",\"event_id\":\"wax:live:proc:1\",\"ts_ns\":1,\"body\":{\"pid\":4242,\"ppid\":42,\"exe_path\":\"/usr/bin/make\",\"argv\":\"make all\"}}");
    n00b_json_node_t *file = record_ok(
        r"{\"schema\":\"wax.normalized.v1\",\"kind\":\"file.modify\",\"event_id\":\"wax:live:file:1\",\"ts_ns\":2,\"body\":{\"pid\":4242,\"path\":\"/tmp/out.o\",\"content_hash\":\"sha256:file\"}}");
    n00b_json_node_t *ai = record_ok(
        r"{\"schema\":\"wax.normalized.v1\",\"kind\":\"ai.api.request_metadata\",\"event_id\":\"wax:live:ai:1\",\"ts_ns\":3,\"body\":{\"session_id\":\"ai-session:1001:1\",\"request_id\":\"req-openai-1\",\"process_ref\":\"process:4242:1:exec:1\",\"repo_ref\":\"repo:fixture\",\"route\":\"/v1/responses\"}}");
    n00b_json_node_t *chalker = record_ok(
        r"{\"schema\":\"wax.normalized.v1\",\"kind\":\"artifact_attestation.policy_decision\",\"event_id\":\"wax:live:chalker:1\",\"ts_ns\":4,\"body\":{\"actor_pid\":4242,\"chalk_id\":\"chalk:6001:1\",\"artifact_ref\":\"artifact:app\",\"artifact_path\":\"/work/repo/build/app\",\"artifact_digest\":\"sha256:app\"}}");

    CHECK(n00b_result_is_ok(n00b_store_ingest(store, proc)));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, file)));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, ai)));
    CHECK(n00b_result_is_ok(n00b_store_ingest(store, chalker)));

    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = 100);
    CHECK(n00b_result_is_ok(seal_r));

    CHECK(query_count(store, eq_filter(r"body.pid", n00b_fv_i64(4242)))
          == 2);
    CHECK(query_count(store,
                      eq_filter(r"body.exe_path",
                                n00b_fv_utf8(r"/usr/bin/make")))
          == 1);
    CHECK(query_count(store,
                      eq_filter(r"body.path", n00b_fv_utf8(r"/tmp/out.o")))
          == 1);
    CHECK(query_count(store,
                      eq_filter(r"body.session_id",
                                n00b_fv_utf8(r"ai-session:1001:1")))
          == 1);
    CHECK(query_count(store,
                      eq_filter(r"body.request_id",
                                n00b_fv_utf8(r"req-openai-1")))
          == 1);
    CHECK(query_count(store,
                      eq_filter(r"body.chalk_id",
                                n00b_fv_utf8(r"chalk:6001:1")))
          == 1);
    CHECK(query_count(store,
                      eq_filter(r"body.artifact_path",
                                n00b_fv_utf8(r"/work/repo/build/app")))
          == 1);
    CHECK(query_count(store, any_contains(r"sha256")) == 2);
    CHECK(query_count(store, any_contains(r"responses")) == 1);

    CHECK(n00b_result_is_ok(n00b_store_close(store)));
}

static void
test_public_store_ingest_and_query(void)
{
    n00b_store_t *store = open_wax_store();
    CHECK(query_count(store, exists_filter(r"kind")) == 0);

    for (uint64_t i = 0; i < 3; i++) {
        auto ingest_r = n00b_store_ingest(store, record_ok(fixture_line(i)));
        CHECK(n00b_result_is_ok(ingest_r));
    }

    CHECK_ERR(n00b_rocs_wax_record_from_line(
                  r"{\"schema\":\"wax.normalized.v1\",\"kind\":\"file.modify\"}"),
              N00B_ROCS_WAX_ERR_MISSING_EVENT_ID);

    auto seal_r = n00b_store_seal_hot_shard(store, .seal_ts = 99);
    CHECK(n00b_result_is_ok(seal_r));

    CHECK(query_count(store, exists_filter(r"kind")) == 3);
    CHECK(query_count(store, eq_filter(r"process.pid", n00b_fv_i64(4242)))
          == 1);
    CHECK(query_count(store,
                      eq_filter(r"process.exe_path",
                                n00b_fv_utf8(r"/usr/bin/make")))
          == 1);
    CHECK(query_count(store,
                      eq_filter(r"file.path", n00b_fv_utf8(r"/tmp/out.o")))
          == 1);
    CHECK(query_count(store,
                      eq_filter(r"ai.session_id",
                                n00b_fv_utf8(r"ai-session:1001:1")))
          == 1);
    CHECK(query_count(store, any_contains(r"codex")) == 1);
    CHECK(query_count(store, any_contains(r"metadata")) == 1);
    // Numbers are not tokenized into the catch-all column (strings only).
    CHECK(query_count(store, any_contains(r"4242")) == 0);
    CHECK(query_count(store, any_contains(r"session")) == 1);
    CHECK(query_count(store, any_contains(r"missingterm")) == 0);

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
    test_live_body_shape_indexes();
    test_public_store_ingest_and_query();

    n00b_shutdown();
    return 0;
}
