/* test/unit/test_rocs_service_runtime.c - WP-012 Phase 2 runtime. */

#include <stdint.h>

#include <errno.h>
#include <string.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/buffer.h"
#include "core/env.h"
#include "core/file.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "net/http/http_client.h"
#include "parsers/json.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "util/path.h"

#include <rocs/n00b_rocs.h>
#include <rocs/service.h>
#include "test_check.h"

static void
set_prefixed_env(n00b_string_t *prefix,
                 n00b_string_t *key,
                 n00b_string_t *value)
{
    n00b_string_t *full_key = n00b_unicode_str_cat(prefix, key);
    CHECK(n00b_putenv(full_key, value));
}

static n00b_string_t *
service_url(uint16_t port, n00b_string_t *path)
{
    return n00b_cformat("http://127.0.0.1:[|#|][|#|]",
                        (int64_t)port,
                        path);
}

static n00b_http_response_t *
response_ok(n00b_result_t(n00b_http_response_t *) rr)
{
    // Name the error. This helper covers every request the file makes,
    // including the 1360 this test's rounds issue, and a bare is_ok check
    // cannot tell a refused connection from a descriptor limit from a
    // timeout -- which is the whole question when it fails partway through
    // a loop.
    if (n00b_result_is_err(rr)) {
        fprintf(stderr,
                "http request failed: err=%lld errno=%d (%s)\n",
                (long long)n00b_result_get_err(rr),
                errno,
                strerror(errno));
    }
    CHECK(n00b_result_is_ok(rr));
    return n00b_result_get(rr);
}

static n00b_http_response_t *
http_post(uint16_t port, n00b_string_t *path, n00b_string_t *body)
{
    return response_ok(n00b_http_request_sync(
        service_url(port, path),
        .method           = r"POST",
        .body             = n00b_buffer_from_bytes(body->data,
                                                   (int64_t)body->u8_bytes),
        .content_type     = r"application/json",
        .allow_plain_http = true));
}

static n00b_http_response_t *
http_get(uint16_t port, n00b_string_t *path)
{
    return response_ok(n00b_http_request_sync(service_url(port, path),
                                              .allow_plain_http = true));
}

static n00b_string_t *
response_text(n00b_http_response_t *resp)
{
    return n00b_buffer_to_string(n00b_http_response_body(resp));
}

static void
check_body_contains(n00b_http_response_t *resp, n00b_string_t *needle)
{
    CHECK(n00b_unicode_str_contains(response_text(resp), needle));
}

static n00b_json_node_t *
response_json(n00b_http_response_t *resp)
{
    n00b_string_t   *text = response_text(resp);
    n00b_json_node_t *json = n00b_json_parse(text->data,
                                             text->u8_bytes,
                                             nullptr);
    CHECK(json != nullptr);
    CHECK(n00b_json_is_object(json));
    return json;
}

static n00b_store_schema_t *
service_schema(void)
{
    auto schema_r = n00b_store_schema_new();
    CHECK(n00b_result_is_ok(schema_r));
    n00b_store_schema_t *schema = n00b_result_get(schema_r);
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(schema, r"id")));
    CHECK(n00b_result_is_ok(n00b_store_schema_add_field(
        schema,
        r"message",
        .index_kind     = N00B_STORE_INDEX_FULLTEXT,
        .include_in_all = true)));
    return schema;
}

static n00b_rocs_service_t *
start_service_on(n00b_string_t    *prefix,
                 bool              read_only,
                 n00b_allocator_t *allocator)
{
    set_prefixed_env(prefix, r"ROCS_PROFILE", r"embedded_local");
    set_prefixed_env(prefix, r"ROCS_HTTP_ADDR", r"127.0.0.1:0");
    set_prefixed_env(prefix,
                     r"ROCS_READ_ONLY",
                     read_only ? r"true" : r"false");

    auto config_r = n00b_rocs_service_config_from_env(.prefix = prefix);
    CHECK(n00b_result_is_ok(config_r));

    auto start_r = n00b_rocs_service_start(n00b_result_get(config_r),
                                           service_schema(),
                                           .allocator = allocator);
    CHECK(n00b_result_is_ok(start_r));
    n00b_rocs_service_t *service = n00b_result_get(start_r);

    auto port_r = n00b_rocs_service_bound_port(service);
    CHECK(n00b_result_is_ok(port_r));
    CHECK(n00b_result_get(port_r) != 0);
    return service;
}

static n00b_rocs_service_t *
start_service(n00b_string_t *prefix, bool read_only)
{
    return start_service_on(prefix, read_only, nullptr);
}

static uint16_t
bound_port(n00b_rocs_service_t *service)
{
    auto port_r = n00b_rocs_service_bound_port(service);
    CHECK(n00b_result_is_ok(port_r));
    return n00b_result_get(port_r);
}

static void
stop_true(n00b_rocs_service_t *service)
{
    auto stop_r = n00b_rocs_service_stop(service);
    CHECK(n00b_result_is_ok(stop_r));
    CHECK(n00b_result_get(stop_r));
}

static void
test_start_stop_and_bound_port(void)
{
    static_assert((N00B_ROCS_CAPABILITIES
                   & N00B_ROCS_CAP_SERVICE_RUNTIME_DECLS)
                  != 0);
    CHECK(n00b_unicode_str_eq(
        n00b_rocs_service_err_str(N00B_ROCS_SERVICE_ERR_HTTP),
        r"HTTP"));

    n00b_rocs_service_t *service =
        start_service(r"ROCS_RT_START_STOP_", false);
    CHECK(bound_port(service) != 0);

    auto stop_r = n00b_rocs_service_stop(service);
    CHECK(n00b_result_is_ok(stop_r));
    CHECK(n00b_result_get(stop_r));
    stop_r = n00b_rocs_service_stop(service);
    CHECK(n00b_result_is_ok(stop_r));
    CHECK(!n00b_result_get(stop_r));

    auto port_r = n00b_rocs_service_bound_port(service);
    CHECK(n00b_result_is_err(port_r));
    CHECK(n00b_result_get_err(port_r) == N00B_ROCS_SERVICE_ERR_CLOSED);
    n00b_printf("  [PASS] start/stop and bound port");
}

static void
test_snapshot_query_request(void)
{
    n00b_rocs_service_t *service =
        start_service(r"ROCS_RT_QUERY_", false);
    uint16_t port = bound_port(service);

    n00b_http_response_t *resp =
        http_post(port,
                  r"/v1/records",
                  r"{\"id\":1,\"message\":\"alpha beta\"}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"ok\":true");

    resp = http_post(port,
                     r"/v1/records",
                     r"{\"id\":2,\"message\":\"gamma\"}");
    CHECK(n00b_http_response_status(resp) == 200);

    resp = http_post(port, r"/v1/flush", r"{}");
    CHECK(n00b_http_response_status(resp) == 200);

    resp = http_post(port,
                     r"/v1/query",
                     r"{\"filter\":{\"exists\":\"id\"},\"limit\":10}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"ok\":true");
    check_body_contains(resp, r"\"count\":2");
    check_body_contains(resp, r"\"generation\":");
    check_body_contains(resp, r"\"shard_id\":");
    check_body_contains(resp, r"\"ordinal\":0");
    check_body_contains(resp, r"\"score\":0");

    resp = http_post(port,
                     r"/v1/query",
                     r"{\"filter\":{\"exists\":\"id\"},\"limit\":1}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":1");
    check_body_contains(resp, r"\"more\":true");
    n00b_json_node_t *first_page = response_json(resp);
    n00b_json_node_t *resume_node =
        n00b_json_object_get(first_page, r"next_resume");
    CHECK(n00b_json_is_string(resume_node));
    n00b_string_t *resume = n00b_json_as_string(resume_node);
    CHECK(resume != nullptr && resume->u8_bytes > 0);

    resp = http_post(
        port,
        r"/v1/query",
        n00b_cformat("{\"filter\":{\"exists\":\"id\"},\"limit\":10,\"resume\":\"[|#|]\"}",
                     resume));
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":1");
    check_body_contains(resp, r"\"more\":false");

    resp = http_post(
        port,
        r"/v1/query",
        r"{\"filter\":{\"contains\":{\"field\":\"message\",\"term\":\"alpha\"}},\"limit\":5}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":1");

    stop_true(service);
    n00b_printf("  [PASS] snapshot query request and cleanup on stop");
}

static void
test_query_cleanup_allows_stop(void)
{
    n00b_rocs_service_t *service =
        start_service(r"ROCS_RT_CLEANUP_", false);
    uint16_t port = bound_port(service);

    n00b_http_response_t *resp =
        http_post(port,
                  r"/v1/records",
                  r"{\"id\":7,\"message\":\"resident cleanup\"}");
    CHECK(n00b_http_response_status(resp) == 200);
    resp = http_post(port, r"/v1/flush", r"{}");
    CHECK(n00b_http_response_status(resp) == 200);

    resp = http_post(
        port,
        r"/v1/query",
        r"{\"filter\":{\"contains\":{\"field\":\"message\",\"term\":\"cleanup\"}},\"limit\":1}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":1");

    /* Leaked query-result pins make store close fail, which makes stop fail. */
    stop_true(service);
    n00b_printf("  [PASS] query cleanup allows stop");
}

static void
test_read_only_mutation_rejection(void)
{
    n00b_rocs_service_t *service =
        start_service(r"ROCS_RT_READ_ONLY_", true);
    uint16_t port = bound_port(service);

    n00b_http_response_t *resp =
        http_post(port, r"/v1/records", r"{\"id\":1}");
    CHECK(n00b_http_response_status(resp) == 403);
    check_body_contains(resp, r"\"read_only\"");

    resp = http_post(port,
                     r"/v1/query",
                     r"{\"filter\":{\"exists\":\"id\"},\"limit\":0}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":0");

    stop_true(service);
    n00b_printf("  [PASS] read-only mutation rejection");
}

#ifdef N00B_DEBUG
typedef struct {
    uint64_t polls;
    uint64_t cancel_after;
} serialize_probe_t;

static bool
serialize_cancel_after_n(void *ctx)
{
    serialize_probe_t *probe = ctx;
    return probe->polls++ >= probe->cancel_after;
}

// The ranked branch copies and encodes every hit under store_mutex after
// n00b_query_run returns, so the budget has to be checked there too. The hook
// is polled once per hit written; firing it on the third must fail the
// request the way an expired budget does, and still release the result.
static void
test_ranked_serialization_honors_budget(void)
{
    n00b_rocs_service_t *service =
        start_service(r"ROCS_RT_SERIALIZE_", false);
    uint16_t port = bound_port(service);

    for (int64_t i = 0; i < 5; i++) {
        n00b_http_response_t *resp = http_post(
            port,
            r"/v1/records",
            n00b_cformat("{\"id\":[|#|],\"message\":\"alpha\"}", i));
        CHECK(n00b_http_response_status(resp) == 200);
    }
    CHECK(n00b_http_response_status(http_post(port, r"/v1/flush", r"{}"))
          == 200);

    n00b_string_t *ranked =
        r"{\"filter\":{\"contains\":{\"field\":\"message\",\"term\":\"alpha\"}},\"ranked\":true,\"include_records\":true,\"limit\":5}";

    serialize_probe_t probe = {.polls = 0, .cancel_after = 2};
    n00b_rocs_service_serialize_cancel_for_test(serialize_cancel_after_n,
                                                &probe);
    n00b_http_response_t *resp = http_post(port, r"/v1/query", ranked);
    n00b_rocs_service_serialize_cancel_for_test(nullptr, nullptr);
    CHECK(n00b_http_response_status(resp) == 504);
    check_body_contains(resp, r"\"query_timeout\"");
    CHECK(probe.polls == 3);

    // Control: the same request with the hook cleared serializes all five.
    resp = http_post(port, r"/v1/query", ranked);
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":5");

    // A leaked result pin would make store close, and so stop, fail.
    stop_true(service);
    n00b_printf("  [PASS] ranked serialization honors the query budget");
}
#endif

static n00b_rocs_service_t *
start_local_service(n00b_string_t *prefix, n00b_string_t *cache_dir)
{
    set_prefixed_env(prefix, r"ROCS_PROFILE", r"service_local");
    set_prefixed_env(prefix, r"ROCS_HTTP_ADDR", r"127.0.0.1:0");
    set_prefixed_env(prefix, r"ROCS_READ_ONLY", r"false");
    set_prefixed_env(prefix, r"ROCS_WRITER_MODE", r"single_writer");
    set_prefixed_env(prefix, r"ROCS_CACHE_DIR", cache_dir);

    auto config_r = n00b_rocs_service_config_from_env(.prefix = prefix);
    CHECK(n00b_result_is_ok(config_r));
    auto start_r = n00b_rocs_service_start(n00b_result_get(config_r),
                                           service_schema());
    CHECK(n00b_result_is_ok(start_r));
    return n00b_result_get(start_r);
}

static n00b_buffer_t *
read_whole_file(n00b_string_t *path)
{
    // STREAM, not the default: a plain read-only open of a regular file
    // resolves to MMAP, and this test rewrites the same path a few lines
    // later. Windows refuses to truncate a file that still has a live
    // section, so the rewrite failed with EINVAL (n00b#472). The library side
    // of that is fixed separately -- close now releases the mapping -- but
    // asking for a stream here says what this code actually wants, and keeps
    // the test independent of which change lands first.
    auto open_r = n00b_file_open(path,
                                 .mode = N00B_FILE_R,
                                 .kind = N00B_FILE_KIND_STREAM);
    // Name the path and the reason: a bare is_ok check cannot separate "no
    // such file" from a sharing or permission refusal, and those point at
    // different fixes.
    if (n00b_result_is_err(open_r)) {
        int e = (int)n00b_result_get_err(open_r);
        fprintf(stderr,
                "open for read failed: path=%s errno=%d (%s)\n",
                path->data,
                e,
                strerror(e));
    }
    CHECK(n00b_result_is_ok(open_r));
    n00b_file_t   *file = n00b_result_get(open_r);
    n00b_buffer_t *all  = n00b_buffer_new(0);
    while (true) {
        auto chunk_r = n00b_file_read(file, 65536);
        CHECK(n00b_result_is_ok(chunk_r));
        n00b_buffer_t *chunk = n00b_result_get(chunk_r);
        if (n00b_buffer_len(chunk) == 0) {
            break;
        }
        n00b_buffer_concat(all, chunk);
    }
    CHECK(n00b_result_is_ok(n00b_file_close_result(file)));
    return all;
}

static void
write_whole_file(n00b_string_t *path, n00b_buffer_t *bytes)
{
    auto open_r = n00b_file_open(path, .mode = N00B_FILE_W);
    if (n00b_result_is_err(open_r)) {
        int e = (int)n00b_result_get_err(open_r);
        fprintf(stderr,
                "open for write failed: path=%s errno=%d (%s)\n",
                path->data,
                e,
                strerror(e));
    }
    CHECK(n00b_result_is_ok(open_r));
    CHECK(n00b_result_is_ok(
        n00b_file_write_all(n00b_result_get(open_r), bytes)));
    CHECK(n00b_result_is_ok(
        n00b_file_close_result(n00b_result_get(open_r))));
}

// A hit whose stored record is damaged must fail the request with a server
// error, never reach the client inside a 200. The query itself still
// succeeds, since the record text is only read when include_records
// serializes it.
static void
test_ranked_serialization_failure_is_an_error(void)
{
    auto tmp_r = n00b_new_temp_dir(r"rocs-rt-serialize-", nullptr);
    CHECK(n00b_result_is_ok(tmp_r));
    n00b_string_t *cache_dir = n00b_result_get(tmp_r);
    n00b_string_t *prefix    = r"ROCS_RT_BADHIT_";

    n00b_rocs_service_t *service = start_local_service(prefix, cache_dir);
    uint16_t             port    = bound_port(service);
    for (int64_t i = 0; i < 3; i++) {
        n00b_http_response_t *resp = http_post(
            port,
            r"/v1/records",
            n00b_cformat("{\"id\":[|#|],\"message\":\"alpha\"}", i));
        CHECK(n00b_http_response_status(resp) == 200);
    }
    CHECK(n00b_http_response_status(http_post(port, r"/v1/flush", r"{}"))
          == 200);
    stop_true(service);

    // Break the stored JSON text of one record in the sealed shard.
    n00b_string_t *shard  = n00b_cformat("[|#|]/rocs/shards/1.n00b",
                                         cache_dir);
    n00b_buffer_t *bytes  = read_whole_file(shard);
    n00b_string_t *needle = r"{\"id\":1,";
    auto           at     = n00b_buffer_find(
        bytes,
        n00b_buffer_from_bytes(needle->data, (int64_t)needle->u8_bytes));
    CHECK(n00b_option_is_set(at));
    bytes->data[n00b_option_get(at) + 5] = '#';
    write_whole_file(shard, bytes);

    service = start_local_service(prefix, cache_dir);
    port    = bound_port(service);

    n00b_http_response_t *resp = http_post(
        port,
        r"/v1/query",
        r"{\"filter\":{\"contains\":{\"field\":\"message\",\"term\":\"alpha\"}},\"ranked\":true,\"include_records\":true,\"limit\":5}");
    CHECK(n00b_http_response_status(resp) == 500);
    check_body_contains(resp, r"\"query_error\"");

    // The snapshot route serves the same stored bytes, so it fails the same way.
    resp = http_post(
        port,
        r"/v1/query",
        r"{\"filter\":{\"contains\":{\"field\":\"message\",\"term\":\"alpha\"}},\"include_records\":true,\"limit\":5}");
    CHECK(n00b_http_response_status(resp) == 500);
    check_body_contains(resp, r"\"query_error\"");

    // Control: without records the same query answers all three hits.
    resp = http_post(
        port,
        r"/v1/query",
        r"{\"filter\":{\"contains\":{\"field\":\"message\",\"term\":\"alpha\"}},\"ranked\":true,\"include_records\":false,\"limit\":5}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":3");

    stop_true(service);
    CHECK(n00b_result_is_ok(
        n00b_path_remove_tree(cache_dir, .ignore_missing = true)));
    n00b_printf("  [PASS] ranked serialization failure is a server error");
}

static void
test_invalid_request_errors(void)
{
    n00b_rocs_service_t *service =
        start_service(r"ROCS_RT_INVALID_", false);
    uint16_t port = bound_port(service);

    n00b_http_response_t *resp =
        http_post(port, r"/v1/query", r"{\"filter\":{\"exists\":5}}");
    CHECK(n00b_http_response_status(resp) == 400);
    check_body_contains(resp, r"\"bad_request\"");

    resp = http_get(port, r"/v1/query");
    CHECK(n00b_http_response_status(resp) == 405);

    stop_true(service);
    n00b_printf("  [PASS] invalid request errors");
}

static void
ingest_ids(uint16_t port, int64_t count)
{
    for (int64_t i = 1; i <= count; i++) {
        n00b_http_response_t *resp = http_post(
            port,
            r"/v1/records",
            n00b_cformat("{\"id\":[|#|],\"message\":\"alpha [|#|]\"}", i, i));
        CHECK(n00b_http_response_status(resp) == 200);
    }
    n00b_http_response_t *resp = http_post(port, r"/v1/flush", r"{}");
    CHECK(n00b_http_response_status(resp) == 200);
}

static n00b_http_response_t *
query_with_limit(uint16_t port, uint64_t limit, bool ranked)
{
    return http_post(
        port,
        r"/v1/query",
        n00b_cformat("{\"filter\":{\"exists\":\"id\"},\"limit\":[|#|],\"ranked\":[|#|]}",
                     (int64_t)limit,
                     ranked ? r"true" : r"false"));
}

static void
test_query_limit_bounds(void)
{
    n00b_rocs_service_t *service = start_service(r"ROCS_RT_LIMIT_", false);
    uint16_t             port    = bound_port(service);
    ingest_ids(port, 3);

    for (int ranked = 0; ranked < 2; ranked++) {
        n00b_http_response_t *resp =
            query_with_limit(port, N00B_ROCS_SERVICE_MAX_QUERY_LIMIT, ranked);
        CHECK(n00b_http_response_status(resp) == 200);
        check_body_contains(resp, r"\"count\":3");

        resp = query_with_limit(port,
                                N00B_ROCS_SERVICE_MAX_QUERY_LIMIT + 1,
                                ranked);
        CHECK(n00b_http_response_status(resp) == 400);
        check_body_contains(resp, r"\"limit_too_large\"");

        resp = query_with_limit(port, 0, ranked);
        CHECK(n00b_http_response_status(resp) == 200);
        check_body_contains(resp, r"\"count\":0");
        check_body_contains(resp, r"\"hits\":[]");
    }

    stop_true(service);
    n00b_printf("  [PASS] query limit bounds");
}

static n00b_string_t *
wide_filter_body(n00b_string_t *op, int64_t terms)
{
    n00b_buffer_t *buf = n00b_buffer_empty();
    n00b_buffer_append_bytes(buf, "{\"filter\":{\"", 12);
    n00b_buffer_append_bytes(buf, op->data, op->u8_bytes);
    n00b_buffer_append_bytes(buf, "\":[", 3);
    for (int64_t i = 0; i < terms; i++) {
        if (i != 0) {
            n00b_buffer_append_bytes(buf, ",", 1);
        }
        if (n00b_unicode_str_eq(op, r"or")) {
            const char *leaf = "{\"eq\":{\"field\":\"id\",\"value\":";
            n00b_buffer_append_bytes(buf, leaf, strlen(leaf));
            n00b_buffer_append_uint(buf, (uint64_t)i);
            n00b_buffer_append_bytes(buf, "}}", 2);
        }
        else {
            const char *leaf = "{\"exists\":\"id\"}";
            n00b_buffer_append_bytes(buf, leaf, strlen(leaf));
        }
    }
    const char *tail = "]},\"limit\":10}";
    n00b_buffer_append_bytes(buf, tail, strlen(tail));
    return n00b_buffer_to_string(buf);
}

static void
test_wide_boolean_filters(void)
{
    n00b_rocs_service_t *service = start_service(r"ROCS_RT_WIDE_", false);
    uint16_t             port    = bound_port(service);
    ingest_ids(port, 3);

    // Four times N00B_FILTER_MAX_DEPTH terms. A left-deep chain of binary
    // nodes is as deep as it is wide and would be rejected as too deep.
    int64_t terms = 4 * (int64_t)N00B_FILTER_MAX_DEPTH;

    n00b_http_response_t *resp =
        http_post(port, r"/v1/query", wide_filter_body(r"or", terms));
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":3");

    resp = http_post(port, r"/v1/query", wide_filter_body(r"and", terms));
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":3");

    stop_true(service);
    n00b_printf("  [PASS] wide boolean filters");
}

static void
check_filter_count(uint16_t port, n00b_string_t *filter, int64_t count)
{
    n00b_http_response_t *resp = http_post(
        port,
        r"/v1/query",
        n00b_cformat("{\"filter\":[|#|],\"limit\":10}", filter));
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, n00b_cformat("\"count\":[|#|]", count));
}

static void
check_filter_rejected(uint16_t port, n00b_string_t *filter)
{
    n00b_http_response_t *resp = http_post(
        port,
        r"/v1/query",
        n00b_cformat("{\"filter\":[|#|],\"limit\":10}", filter));
    CHECK(n00b_http_response_status(resp) == 400);
    check_body_contains(resp, r"\"bad_request\"");
}

static void
test_filter_kinds(void)
{
    n00b_rocs_service_t *service = start_service(r"ROCS_RT_KINDS_", false);
    uint16_t             port    = bound_port(service);
    ingest_ids(port, 3);

    check_filter_count(port, r"{\"exists\":\"id\"}", 3);
    check_filter_count(
        port,
        r"{\"contains\":{\"field\":\"message\",\"term\":\"alpha\"}}",
        3);
    check_filter_count(port,
                       r"{\"contains\":{\"any\":true,\"term\":\"alpha\"}}",
                       3);
    check_filter_count(port, r"{\"eq\":{\"field\":\"id\",\"value\":2}}", 1);
    check_filter_count(
        port,
        r"{\"range\":{\"field\":\"id\",\"lower\":0,\"upper\":10}}",
        3);
    check_filter_count(
        port,
        r"{\"prefix\":{\"field\":\"message\",\"prefix\":\"alp\"}}",
        3);
    check_filter_count(
        port,
        r"{\"regex\":{\"field\":\"message\",\"pattern\":\"alpha.*\"}}",
        3);
    check_filter_count(
        port,
        r"{\"and\":[{\"or\":[{\"eq\":{\"field\":\"id\",\"value\":1}},{\"eq\":{\"field\":\"id\",\"value\":2}}]},{\"exists\":\"id\"}]}",
        2);
    check_filter_count(
        port,
        r"{\"or\":[{\"eq\":{\"field\":\"id\",\"value\":3}}]}",
        1);
    // A leaf key wins over a boolean key in the same object.
    check_filter_count(
        port,
        r"{\"eq\":{\"field\":\"id\",\"value\":1},\"or\":[{\"exists\":\"id\"},{\"exists\":\"id\"}]}",
        1);

    check_filter_rejected(port, r"{\"or\":[]}");
    check_filter_rejected(port, r"{\"and\":{\"exists\":\"id\"}}");
    check_filter_rejected(port, r"{\"and\":[{\"exists\":\"id\"},5]}");
    check_filter_rejected(port, r"{\"bogus\":1}");
    check_filter_rejected(port, r"{\"eq\":5,\"or\":[{\"exists\":\"id\"}]}");

    stop_true(service);
    n00b_printf("  [PASS] filter kinds");
}

static void
check_records_are_json(uint16_t port, int64_t expected)
{
    n00b_http_response_t *resp = http_post(
        port,
        r"/v1/query",
        r"{\"filter\":{\"exists\":\"id\"},\"limit\":50,\"include_records\":true}");
    CHECK(n00b_http_response_status(resp) == 200);
    n00b_json_node_t *hits =
        n00b_json_object_get(response_json(resp), r"hits");
    CHECK(hits != nullptr && n00b_json_is_array(hits));
    n00b_json_array_t *items = n00b_json_as_array(hits);
    CHECK((int64_t)n00b_list_len(*items) == expected);
    for (size_t i = 0; i < n00b_list_len(*items); i++) {
        n00b_json_node_t *record =
            n00b_json_object_get(n00b_list_get(*items, i), r"record");
        CHECK(record != nullptr && n00b_json_is_object(record));
        CHECK(n00b_json_is_int(n00b_json_object_get(record, r"id")));
        CHECK(n00b_json_is_string(n00b_json_object_get(record, r"message")));
    }
}

// The bytes of the only hit's "record" in an unranked include_records reply.
static n00b_string_t *
only_record_text(uint16_t port)
{
    n00b_http_response_t *resp = http_post(
        port,
        r"/v1/query",
        r"{\"filter\":{\"exists\":\"id\"},\"limit\":10,\"include_records\":true}");
    CHECK(n00b_http_response_status(resp) == 200);
    n00b_string_t *text  = response_text(resp);
    const char    *start = strstr(text->data, "\"record\":");
    const char    *end   = strstr(text->data, "}],\"count\":1,");
    CHECK(start != nullptr && end != nullptr && start < end);
    start += strlen("\"record\":");
    return n00b_string_from_raw(start, (int64_t)(end - start));
}

static void
test_sealed_records_are_returned_as_stored(void)
{
    n00b_rocs_service_t *service = start_service(r"ROCS_RT_BYTES_", false);
    uint16_t             port    = bound_port(service);

    // A double whose compact encoding does not survive a second parse and
    // encode, so the reply differs from the stored bytes if the service
    // re-encodes the record.
    n00b_string_t *record =
        r"{\"id\":1,\"message\":\"alpha\",\"d\":123456789.123456789}";
    n00b_http_response_t *resp = http_post(port, r"/v1/records", record);
    CHECK(n00b_http_response_status(resp) == 200);
    resp = http_post(port, r"/v1/flush", r"{}");
    CHECK(n00b_http_response_status(resp) == 200);

    // The store seals a record as the compact encoding of its parsed body.
    n00b_json_node_t *parsed =
        n00b_json_parse(record->data, record->u8_bytes, nullptr);
    CHECK(parsed != nullptr);
    char *stored = n00b_json_encode(parsed, .pretty = false);
    CHECK(stored != nullptr);

    CHECK(n00b_unicode_str_eq(only_record_text(port),
                              n00b_string_from_cstr(stored)));

    stop_true(service);
    n00b_printf("  [PASS] sealed records are returned as stored");
}

static void
request_round(uint16_t port)
{
    n00b_http_response_t *resp = http_post(
        port,
        r"/v1/query",
        r"{\"filter\":{\"exists\":\"id\"},\"limit\":50,\"include_records\":true}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":24");

    resp = http_post(
        port,
        r"/v1/query",
        r"{\"filter\":{\"contains\":{\"field\":\"message\",\"term\":\"alpha\"}},\"limit\":50,\"ranked\":true,\"include_records\":true}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":12");

    resp = http_post(port, r"/v1/query", r"{\"filter\":{\"exists\":5}}");
    CHECK(n00b_http_response_status(resp) == 400);

    resp = http_get(port, r"/healthz/ready");
    CHECK(n00b_http_response_status(resp) == 200);
    resp = http_get(port, r"/metrics");
    CHECK(n00b_http_response_status(resp) == 200);
}

static void
test_requests_do_not_grow_service_allocator(void)
{
    const uint64_t     rounds          = 256;
    const uint64_t     max_round_bytes = 16 * 1024;
    static n00b_pool_t long_lived;
    n00b_allocator_t  *allocator =
        n00b_pool_init(&long_lived,
                       .hidden            = true,
                       .external_metadata = true,
                       .name              = "test_rocs_service_long_lived");
    n00b_rocs_service_t *service =
        start_service_on(r"ROCS_RT_RETAIN_", false, allocator);
    uint16_t port = bound_port(service);

    for (int64_t i = 0; i < 24; i++) {
        n00b_http_response_t *resp = http_post(
            port,
            r"/v1/records",
            n00b_cformat("{\"id\":[|#|],\"message\":\"[|#|] record [|#|]\"}",
                         i,
                         (i % 2) == 0 ? r"alpha" : r"beta",
                         i));
        CHECK(n00b_http_response_status(resp) == 200);
        if (i == 11) {
            resp = http_post(port, r"/v1/flush", r"{}");
            CHECK(n00b_http_response_status(resp) == 200);
        }
    }
    // Twelve sealed records and twelve still in the hot shard.
    check_records_are_json(port, 24);
    n00b_http_response_t *resp = http_post(port, r"/v1/flush", r"{}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_records_are_json(port, 24);

    for (int i = 0; i < 16; i++) {
        request_round(port);
    }
    uint64_t before = n00b_pool_mapped_bytes(&long_lived);
    for (uint64_t i = 0; i < rounds; i++) {
        request_round(port);
    }
    uint64_t after = n00b_pool_mapped_bytes(&long_lived);

    // n00b_store_map_root cuts each root shard handle from the map's
    // allocator: one per shard an unranked query opens and one per hit a
    // ranked query materializes, about 3KB per round here. The bound allows
    // that and fails on any per-request view, cursor, parsed body, or reply
    // kept here, which together come to hundreds of KB per round.
    CHECK(after - before <= rounds * max_round_bytes);

    stop_true(service);
    n00b_allocator_destroy(allocator);
    n00b_printf("  [PASS] requests do not grow the service allocator");
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    n00b_printf("test_rocs_service_runtime:");
    test_start_stop_and_bound_port();
    test_snapshot_query_request();
    test_query_cleanup_allows_stop();
    test_read_only_mutation_rejection();
    test_invalid_request_errors();
    test_ranked_serialization_failure_is_an_error();
#ifdef N00B_DEBUG
    test_ranked_serialization_honors_budget();
#endif
    test_query_limit_bounds();
    test_wide_boolean_filters();
    test_filter_kinds();
    test_sealed_records_are_returned_as_stored();
    test_requests_do_not_grow_service_allocator();
    n00b_shutdown();
    return 0;
}
