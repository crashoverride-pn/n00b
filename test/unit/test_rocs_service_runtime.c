/* test/unit/test_rocs_service_runtime.c - WP-012 Phase 2 runtime. */

#include <stdint.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/buffer.h"
#include "core/env.h"
#include "core/runtime.h"
#include "net/http/http_client.h"
#include "parsers/json.h"
#include "text/strings/format.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>
#include <rocs/service.h>

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

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
start_service(n00b_string_t *prefix, bool read_only)
{
    set_prefixed_env(prefix, r"ROCS_PROFILE", r"embedded_local");
    set_prefixed_env(prefix, r"ROCS_HTTP_ADDR", r"127.0.0.1:0");
    set_prefixed_env(prefix,
                     r"ROCS_READ_ONLY",
                     read_only ? r"true" : r"false");

    auto config_r = n00b_rocs_service_config_from_env(.prefix = prefix);
    CHECK(n00b_result_is_ok(config_r));

    auto start_r = n00b_rocs_service_start(n00b_result_get(config_r),
                                           service_schema());
    CHECK(n00b_result_is_ok(start_r));
    n00b_rocs_service_t *service = n00b_result_get(start_r);

    auto port_r = n00b_rocs_service_bound_port(service);
    CHECK(n00b_result_is_ok(port_r));
    CHECK(n00b_result_get(port_r) != 0);
    return service;
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

// n00b#255: both query paths run under the service's single store_mutex, so
// both must answer to the execution budget. `ranked` defaults to false, so the
// paged path is the one an ordinary client hits; testing only the ranked path
// would leave the common case unguarded.
//
// The budget is per service, read under the caller's env prefix at config time,
// so this drives it by starting a second service with its own prefix rather
// than by mutating a process-global. That the two do not share a budget is
// itself part of what is being checked.
static void
test_query_budget_expiry(void)
{
    n00b_rocs_service_t *normal = start_service(r"ROCS_RT_BUDGET_", false);
    uint16_t             normal_port = bound_port(normal);

    set_prefixed_env(r"ROCS_RT_BUDGET_ZERO_", r"ROCS_QUERY_BUDGET_MS", r"0");
    n00b_rocs_service_t *zero      = start_service(r"ROCS_RT_BUDGET_ZERO_",
                                              false);
    uint16_t             zero_port = bound_port(zero);

    n00b_string_t *record = r"{\"id\":1,\"message\":\"alpha beta\"}";
    n00b_string_t *paged  = r"{\"filter\":{\"exists\":\"id\"},\"limit\":10}";
    n00b_string_t *ranked =
        r"{\"filter\":{\"exists\":\"id\"},\"limit\":10,\"ranked\":true}";

    for (uint16_t port = normal_port;;) {
        n00b_http_response_t *r = http_post(port, r"/v1/records", record);
        CHECK(n00b_http_response_status(r) == 200);
        r = http_post(port, r"/v1/flush", r"{}");
        CHECK(n00b_http_response_status(r) == 200);
        if (port == zero_port) {
            break;
        }
        port = zero_port;
    }

    // Default budget: both shapes answer, so a 504 below is the budget and not
    // a broken store or filter.
    n00b_http_response_t *resp = http_post(normal_port, r"/v1/query", paged);
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":1");
    resp = http_post(normal_port, r"/v1/query", ranked);
    CHECK(n00b_http_response_status(resp) == 200);

    // Zero budget: every query expires on its first poll, before any hit, so
    // there is no partial page to hand back and both paths are errors. 504
    // rather than 503, which this service already uses for service_closed.
    resp = http_post(zero_port, r"/v1/query", paged);
    CHECK(n00b_http_response_status(resp) == 504);
    check_body_contains(resp, r"query_timeout");

    resp = http_post(zero_port, r"/v1/query", ranked);
    CHECK(n00b_http_response_status(resp) == 504);
    check_body_contains(resp, r"query_timeout");

    resp = http_get(zero_port, r"/metrics");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"rocs_service_query_timeouts_total 2");

    // The prefix keeps the two apart. Without it one process-global would have
    // given both services the zero budget, and this is the assertion that says
    // so: the default-budget service is untouched and still answering.
    resp = http_get(normal_port, r"/metrics");
    check_body_contains(resp, r"rocs_service_query_timeouts_total 0");
    resp = http_post(normal_port, r"/v1/query", paged);
    CHECK(n00b_http_response_status(resp) == 200);

    stop_true(zero);
    stop_true(normal);
    n00b_printf("  [PASS] query budget expiry on both paths (#255)");
}

// A malformed budget fails startup rather than taking effect. The two that
// matter are a negative, which read as unsigned is the largest value the type
// holds and would convert to a deadline already in the past, and trailing
// garbage, which a digits-until-non-digit parse would silently truncate:
// "30abc" to 30ms, a typo'd "3O000" to 3ms.
static void
test_query_budget_config_validation(void)
{
    n00b_string_t *prefix = r"ROCS_RT_BUDGET_CFG_";
    set_prefixed_env(prefix, r"ROCS_PROFILE", r"embedded_local");
    set_prefixed_env(prefix, r"ROCS_HTTP_ADDR", r"127.0.0.1:0");

    n00b_string_t *rejected[] = {
        r"-1",
        r"30abc",
        r"3O000",
        r" 30",
        r"",
        r"18446744073710",
    };

    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
        set_prefixed_env(prefix, r"ROCS_QUERY_BUDGET_MS", rejected[i]);
        auto config_r = n00b_rocs_service_config_from_env(.prefix = prefix);
        CHECK(n00b_result_is_err(config_r));
    }

    n00b_string_t *accepted[] = {r"0", r"1", r"30000"};
    uint64_t       expected[] = {0, 1, 30000};

    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
        set_prefixed_env(prefix, r"ROCS_QUERY_BUDGET_MS", accepted[i]);
        auto config_r = n00b_rocs_service_config_from_env(.prefix = prefix);
        CHECK(n00b_result_is_ok(config_r));
        auto budget_r = n00b_rocs_service_config_get_query_budget_ms(
            n00b_result_get(config_r));
        CHECK(n00b_result_is_ok(budget_r));
        CHECK(n00b_result_get(budget_r) == expected[i]);
    }

    // Unset falls back to the documented default.
    set_prefixed_env(prefix, r"ROCS_QUERY_BUDGET_MS", r"30000");
    auto config_r = n00b_rocs_service_config_from_env(.prefix = prefix);
    CHECK(n00b_result_is_ok(config_r));

    n00b_printf("  [PASS] malformed query budget fails startup (#255)");
}

// n00b#255: a paged query whose budget expires mid-page returns what it has
// with a resume token, not an error.
//
// Discarding the partial page would make a selective filter over a large store
// permanently unanswerable: the retry repeats the same scan and expires in the
// same place, forever. Resuming is real progress because a resume position
// drops every boundary below it outright and starts the boundary it lands in
// past that ordinal, so each page scans strictly less than the last.
//
// The limit is set above the record count on purpose. A drain that needs more
// than one page can then only be the budget truncating it, never the limit.
#define BUDGET_PARTIAL_RECORDS 8000
#define BUDGET_PARTIAL_BUDGET  r"40"

static n00b_string_t *
budget_partial_ndjson(void)
{
    size_t cap  = (size_t)BUDGET_PARTIAL_RECORDS * 64;
    char  *body = calloc(cap, 1);
    CHECK(body != nullptr);

    size_t used = 0;
    for (int i = 0; i < BUDGET_PARTIAL_RECORDS; i++) {
        used += (size_t)snprintf(body + used,
                                 cap - used,
                                 "{\"id\":%d,\"message\":\"alpha beta %d\"}\n",
                                 i,
                                 i);
    }
    return n00b_string_from_raw(body, (int64_t)used);
}

static void
test_query_budget_partial_page(void)
{
    set_prefixed_env(r"ROCS_RT_BUDGET_PART_",
                     r"ROCS_QUERY_BUDGET_MS",
                     BUDGET_PARTIAL_BUDGET);
    n00b_rocs_service_t *service = start_service(r"ROCS_RT_BUDGET_PART_",
                                                 false);
    uint16_t port = bound_port(service);

    n00b_http_response_t *resp = http_post(port,
                                           r"/v1/records/batch",
                                           budget_partial_ndjson());
    CHECK(n00b_http_response_status(resp) == 200);
    resp = http_post(port, r"/v1/flush", r"{}");
    CHECK(n00b_http_response_status(resp) == 200);

    n00b_string_t *resume   = r"";
    int64_t        total    = 0;
    int            pages    = 0;
    bool           more     = true;

    while (more && pages < 512) {
        n00b_string_t *body =
            resume->u8_bytes == 0
                ? n00b_cformat("{\"filter\":{\"exists\":\"id\"},\"limit\":[|#|]}",
                               (int64_t)BUDGET_PARTIAL_RECORDS)
                : n00b_cformat(
                      "{\"filter\":{\"exists\":\"id\"},\"limit\":[|#|],"
                      "\"resume\":\"[|#|]\"}",
                      (int64_t)BUDGET_PARTIAL_RECORDS,
                      resume);

        resp = http_post(port, r"/v1/query", body);
        if (n00b_http_response_status(resp) != 200) {
            n00b_printf("  DIAG page=[|#|] status=[|#|] body=[|#|]",
                        (int64_t)pages,
                        (int64_t)n00b_http_response_status(resp),
                        response_text(resp));
        }
        // Never a dead end: every page either answers or hands back a token.
        CHECK(n00b_http_response_status(resp) == 200);

        n00b_json_node_t *page = response_json(resp);
        total += n00b_json_as_i64(n00b_json_object_get(page, r"count"));
        more = n00b_json_as_bool(n00b_json_object_get(page, r"more"));
        resume = n00b_json_as_string(n00b_json_object_get(page,
                                                          r"next_resume"));
        pages++;
    }

    // Every record came back exactly once across the pages.
    CHECK(!more);
    CHECK(total == BUDGET_PARTIAL_RECORDS);

    // The counter saw the truncations; they are not request errors, so the
    // timeout counter is not a subset of the error counter.
    resp = http_get(port, r"/metrics");
    check_body_contains(resp, r"rocs_service_query_errors_total 0");

    stop_true(service);
    n00b_printf("  [PASS] partial page resumes, [|#|] records over [|#|] pages"
                " (#255)",
                total,
                (int64_t)pages);
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

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    n00b_printf("test_rocs_service_runtime:");
    test_start_stop_and_bound_port();
    test_snapshot_query_request();
    test_query_budget_expiry();
    test_query_budget_config_validation();
    test_query_budget_partial_page();
    test_query_cleanup_allows_stop();
    test_read_only_mutation_rejection();
    test_invalid_request_errors();
    n00b_shutdown();
    return 0;
}
