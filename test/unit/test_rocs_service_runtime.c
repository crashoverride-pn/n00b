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
// ROCS_QUERY_BUDGET_MS=0 expires every query on its first poll, which makes the
// expiry deterministic instead of a 30-second wait.
//
// n00b_putenv is documented as unsynchronized against concurrent readers, and
// the handler reads this variable per request. Every mutation below sits
// between a completed response and the next request, so no handler thread is
// reading while it happens.
static void
test_query_budget_expiry(void)
{
    n00b_rocs_service_t *service =
        start_service(r"ROCS_RT_BUDGET_", false);
    uint16_t port = bound_port(service);

    n00b_http_response_t *resp =
        http_post(port,
                  r"/v1/records",
                  r"{\"id\":1,\"message\":\"alpha beta\"}");
    CHECK(n00b_http_response_status(resp) == 200);

    resp = http_post(port, r"/v1/flush", r"{}");
    CHECK(n00b_http_response_status(resp) == 200);

    // Baseline: both shapes answer normally on the default budget, so a 503
    // below is the budget and not a broken store or filter.
    resp = http_post(port,
                     r"/v1/query",
                     r"{\"filter\":{\"exists\":\"id\"},\"limit\":10}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":1");

    resp = http_post(
        port,
        r"/v1/query",
        r"{\"filter\":{\"exists\":\"id\"},\"limit\":10,\"ranked\":true}");
    CHECK(n00b_http_response_status(resp) == 200);

    CHECK(n00b_putenv(r"ROCS_QUERY_BUDGET_MS", r"0"));

    // The paged path, which is what a request without "ranked" takes.
    resp = http_post(port,
                     r"/v1/query",
                     r"{\"filter\":{\"exists\":\"id\"},\"limit\":10}");
    CHECK(n00b_http_response_status(resp) == 503);
    check_body_contains(resp, r"query_timeout");

    // The ranked path.
    resp = http_post(
        port,
        r"/v1/query",
        r"{\"filter\":{\"exists\":\"id\"},\"limit\":10,\"ranked\":true}");
    CHECK(n00b_http_response_status(resp) == 503);
    check_body_contains(resp, r"query_timeout");

    // An expiry gets its own counter ON TOP OF the generic query error total,
    // so an operator can tell a stalling store from a failing one. The timeout
    // counter is a subset of the error counter, not a separate total.
    resp = http_get(port, r"/metrics");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"rocs_service_query_timeouts_total 2");

    // A value that is not a non-negative count of milliseconds falls back to
    // the default rather than being taken literally. "-1" is the case that
    // matters: read as unsigned it is ULLONG_MAX, and multiplying it into
    // nanoseconds wraps to a deadline in the PAST, so the operator writing it
    // for "no limit" would get every query expiring instead.
    CHECK(n00b_putenv(r"ROCS_QUERY_BUDGET_MS", r"-1"));
    resp = http_post(port,
                     r"/v1/query",
                     r"{\"filter\":{\"exists\":\"id\"},\"limit\":10}");
    CHECK(n00b_http_response_status(resp) == 200);

    // Too large to parse at all: same fallback.
    CHECK(n00b_putenv(r"ROCS_QUERY_BUDGET_MS", r"99999999999999999999"));
    resp = http_post(port,
                     r"/v1/query",
                     r"{\"filter\":{\"exists\":\"id\"},\"limit\":10}");
    CHECK(n00b_http_response_status(resp) == 200);

    // Parses, but is more milliseconds than fit in nanoseconds. This one takes
    // the clamp and the saturating deadline rather than the fallback, and must
    // mean a budget that never expires, not one that already has.
    CHECK(n00b_putenv(r"ROCS_QUERY_BUDGET_MS", r"100000000000000"));
    resp = http_post(port,
                     r"/v1/query",
                     r"{\"filter\":{\"exists\":\"id\"},\"limit\":10}");
    CHECK(n00b_http_response_status(resp) == 200);

    // The counter did not move: neither malformed value expired anything.
    resp = http_get(port, r"/metrics");
    check_body_contains(resp, r"rocs_service_query_timeouts_total 2");

    // Clear rather than restore a literal default, which would silently pin
    // the tests that follow to today's value if the default ever moves. The
    // handler reads an empty value as unset.
    CHECK(n00b_putenv(r"ROCS_QUERY_BUDGET_MS", r""));

    // Ingest still works: the point of bounding a query is that it releases
    // store_mutex instead of holding it, so the next writer is not blocked.
    resp = http_post(port,
                     r"/v1/records",
                     r"{\"id\":2,\"message\":\"gamma\"}");
    CHECK(n00b_http_response_status(resp) == 200);

    resp = http_post(port,
                     r"/v1/query",
                     r"{\"filter\":{\"exists\":\"id\"},\"limit\":10}");
    CHECK(n00b_http_response_status(resp) == 200);

    stop_true(service);
    n00b_printf("  [PASS] query budget expiry on both paths (#255)");
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
    test_query_cleanup_allows_stop();
    test_read_only_mutation_rejection();
    test_invalid_request_errors();
    n00b_shutdown();
    return 0;
}
