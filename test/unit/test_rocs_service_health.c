/* test/unit/test_rocs_service_health.c - WP-012 Phase 3 health/metrics. */

#include <stdint.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/buffer.h"
#include "core/env.h"
#include "core/runtime.h"
#include "net/http/http_client.h"
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
http_get(uint16_t port, n00b_string_t *path)
{
    return response_ok(n00b_http_request_sync(service_url(port, path),
                                              .allow_plain_http = true));
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

static bool
metric_name_at(n00b_string_t *text, uint64_t offset, n00b_string_t *name)
{
    if (text == nullptr || name == nullptr
        || offset + name->u8_bytes >= text->u8_bytes) {
        return false;
    }
    for (uint64_t i = 0; i < name->u8_bytes; i++) {
        if (text->data[offset + i] != name->data[i]) {
            return false;
        }
    }
    return text->data[offset + name->u8_bytes] == ' ';
}

static uint64_t
metric_value(n00b_http_response_t *resp, n00b_string_t *name)
{
    n00b_string_t *text = response_text(resp);
    for (uint64_t i = 0; i < text->u8_bytes; i++) {
        if (i != 0 && text->data[i - 1] != '\n') {
            continue;
        }
        if (!metric_name_at(text, i, name)) {
            continue;
        }

        uint64_t j     = i + name->u8_bytes + 1;
        uint64_t value = 0;
        bool     saw   = false;
        while (j < text->u8_bytes && text->data[j] >= '0'
               && text->data[j] <= '9') {
            value = value * 10u + (uint64_t)(text->data[j] - '0');
            saw   = true;
            j++;
        }
        CHECK(saw);
        return value;
    }
    CHECK(false);
    return 0;
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
start_service_with_resident_shards(n00b_string_t *prefix,
                                   n00b_string_t *resident_shards)
{
    set_prefixed_env(prefix, r"ROCS_PROFILE", r"embedded_local");
    set_prefixed_env(prefix, r"ROCS_HTTP_ADDR", r"127.0.0.1:0");
    set_prefixed_env(prefix, r"ROCS_READ_ONLY", r"false");
    if (resident_shards != nullptr) {
        set_prefixed_env(prefix, r"ROCS_RESIDENT_SHARDS", resident_shards);
    }

    auto config_r = n00b_rocs_service_config_from_env(.prefix = prefix);
    CHECK(n00b_result_is_ok(config_r));

    auto start_r = n00b_rocs_service_start(n00b_result_get(config_r),
                                           service_schema());
    CHECK(n00b_result_is_ok(start_r));
    return n00b_result_get(start_r);
}

static n00b_rocs_service_t *
start_service(n00b_string_t *prefix)
{
    return start_service_with_resident_shards(prefix, nullptr);
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
test_health_transitions(void)
{
    static_assert((N00B_ROCS_CAPABILITIES
                   & N00B_ROCS_CAP_SERVICE_HEALTH_DECLS)
                  != 0);

    n00b_rocs_service_t *service = start_service(r"ROCS_HEALTH_PROBES_");
    uint16_t             port    = bound_port(service);

    n00b_http_response_t *resp = http_get(port, r"/healthz/startup");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"started\"");

    resp = http_get(port, r"/healthz/live");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"alive\"");

    resp = http_get(port, r"/healthz/ready");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"ready\"");

    CHECK(n00b_result_is_ok(
        n00b_rocs_service_set_dependency_ready(service, false)));
    resp = http_get(port, r"/healthz/ready");
    CHECK(n00b_http_response_status(resp) == 503);
    check_body_contains(resp, r"\"not_ready\"");
    check_body_contains(resp, r"\"dependency_ready\":false");

    resp = http_get(port, r"/healthz/live");
    CHECK(n00b_http_response_status(resp) == 200);

    CHECK(n00b_result_is_ok(
        n00b_rocs_service_set_dependency_ready(service, true)));
    CHECK(n00b_result_is_ok(n00b_rocs_service_set_draining(service, true)));
    resp = http_get(port, r"/healthz/ready");
    CHECK(n00b_http_response_status(resp) == 503);
    check_body_contains(resp, r"\"draining\":true");

    resp = http_get(port, r"/healthz/live");
    CHECK(n00b_http_response_status(resp) == 200);

    CHECK(n00b_result_is_ok(n00b_rocs_service_set_draining(service, false)));
    resp = http_get(port, r"/healthz/ready");
    CHECK(n00b_http_response_status(resp) == 200);

    stop_true(service);
    auto closed_r = n00b_rocs_service_set_draining(service, false);
    CHECK(n00b_result_is_err(closed_r));
    CHECK(n00b_result_get_err(closed_r) == N00B_ROCS_SERVICE_ERR_CLOSED);
    n00b_printf("  [PASS] startup/liveness/readiness transitions");
}

static void
test_metrics_updates(void)
{
    n00b_rocs_service_t *service =
        start_service_with_resident_shards(r"ROCS_HEALTH_METRICS_", r"2");
    uint16_t             port    = bound_port(service);

    n00b_http_response_t *resp = http_get(port, r"/metrics");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"# TYPE rocs_service_ready gauge");
    check_body_contains(resp, r"# TYPE rocs_store_resident_bytes gauge");
    check_body_contains(resp, r"# TYPE rocs_store_resident_shards gauge");
    check_body_contains(resp, r"# TYPE rocs_store_catalog_generation gauge");
    check_body_contains(resp, r"# TYPE rocs_service_vfs_s3_errors_total counter");
    check_body_contains(resp, r"# TYPE rocs_service_cache_hits_total counter");
    check_body_contains(resp, r"# TYPE rocs_service_cache_misses_total counter");
    check_body_contains(resp, r"# TYPE rocs_service_query_latency_ns_total counter");
    check_body_contains(resp, r"# TYPE rocs_service_live_queue_pressure gauge");

    CHECK(n00b_result_is_ok(
        n00b_rocs_service_set_dependency_ready(service, false)));
    CHECK(n00b_result_is_ok(
        n00b_rocs_service_set_dependency_ready(service, true)));
    CHECK(n00b_result_is_ok(
        n00b_rocs_service_set_live_queue_pressure(service, 7)));

    resp = http_post(port,
                     r"/v1/records",
                     r"{\"id\":1,\"message\":\"alpha beta\"}");
    CHECK(n00b_http_response_status(resp) == 200);
    resp = http_post(port, r"/v1/flush", r"{}");
    CHECK(n00b_http_response_status(resp) == 200);

    resp = http_post(port,
                     r"/v1/records",
                     r"{\"id\":2,\"message\":\"alpha gamma\"}");
    CHECK(n00b_http_response_status(resp) == 200);
    resp = http_post(port, r"/v1/flush", r"{}");
    CHECK(n00b_http_response_status(resp) == 200);

    resp = http_post(port,
                     r"/v1/records",
                     r"{\"id\":3,\"message\":\"alpha delta\"}");
    CHECK(n00b_http_response_status(resp) == 200);
    resp = http_post(port, r"/v1/flush", r"{}");
    CHECK(n00b_http_response_status(resp) == 200);

    resp = http_post(port, r"/v1/records", r"not-json");
    CHECK(n00b_http_response_status(resp) == 400);

    resp = http_post(port,
                     r"/v1/query",
                     r"{\"filter\":{\"exists\":\"id\"},\"limit\":10}");
    CHECK(n00b_http_response_status(resp) == 200);

    resp = http_post(port,
                     r"/v1/query",
                     r"{\"filter\":{\"exists\":\"id\"},\"limit\":10}");
    CHECK(n00b_http_response_status(resp) == 200);

    resp = http_post(port, r"/v1/query", r"{\"filter\":{\"exists\":5}}");
    CHECK(n00b_http_response_status(resp) == 400);

    resp = http_get(port, r"/metrics");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"rocs_service_ingest_requests_total 7");
    check_body_contains(resp, r"rocs_service_ingest_errors_total 1");
    check_body_contains(resp, r"rocs_service_query_requests_total 3");
    check_body_contains(resp, r"rocs_service_query_errors_total 1");
    check_body_contains(resp, r"rocs_service_store_errors_total 1");
    CHECK(metric_value(resp, r"rocs_service_vfs_s3_errors_total") == 1);
    CHECK(metric_value(resp, r"rocs_service_cache_hits_total") > 0);
    CHECK(metric_value(resp, r"rocs_service_cache_misses_total") > 0);
    CHECK(metric_value(resp, r"rocs_service_trim_unloads_total") > 0);
    CHECK(metric_value(resp, r"rocs_service_live_queue_pressure") == 7);
    check_body_contains(resp, r"rocs_store_catalog_entries 3");
    check_body_contains(resp, r"rocs_service_query_latency_ns_total ");
    check_body_contains(resp, r"rocs_service_ingest_latency_ns_total ");

    stop_true(service);
    n00b_printf("  [PASS] metrics names and representative updates");
}

static void
test_invalid_method_and_path(void)
{
    n00b_rocs_service_t *service = start_service(r"ROCS_HEALTH_INVALID_");
    uint16_t             port    = bound_port(service);

    n00b_http_response_t *resp = http_post(port, r"/metrics", r"{}");
    CHECK(n00b_http_response_status(resp) == 405);

    resp = http_get(port, r"/no-such-health-path");
    CHECK(n00b_http_response_status(resp) == 404);

    stop_true(service);
    n00b_printf("  [PASS] invalid method/path behavior");
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    n00b_printf("test_rocs_service_health:");
    test_health_transitions();
    test_metrics_updates();
    test_invalid_method_and_path();
    n00b_shutdown();
    return 0;
}
