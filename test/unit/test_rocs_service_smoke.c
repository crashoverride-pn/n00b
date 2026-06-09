/* test/unit/test_rocs_service_smoke.c - WP-012 Phase 5 deployment smoke. */

#include <stdint.h>

#include "n00b.h"
#include "conduit/print.h"
#include "core/buffer.h"
#include "core/env.h"
#include "core/runtime.h"
#include "net/http/http_client.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>
#include <rocs/service.h>
#include <rocs/store.h>

#define ROCS_SERVICE_SMOKE_SKIP 77

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

static bool
string_empty(n00b_string_t *s)
{
    return s == nullptr || s->data == nullptr || s->u8_bytes == 0;
}

static void
set_prefixed_env(n00b_string_t *prefix,
                 n00b_string_t *key,
                 n00b_string_t *value)
{
    n00b_string_t *full_key = n00b_unicode_str_cat(prefix, key);
    CHECK(n00b_putenv(full_key, value));
}

static void
ensure_env(n00b_string_t *key, n00b_string_t *value)
{
    if (string_empty(n00b_getenv(key))) {
        CHECK(n00b_putenv(key, value));
    }
}

static int
skip(n00b_string_t *reason)
{
    n00b_printf("[SKIP] [|#|]", reason);
    return ROCS_SERVICE_SMOKE_SKIP;
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

static uint16_t
bound_port(n00b_rocs_service_t *service)
{
    auto port_r = n00b_rocs_service_bound_port(service);
    CHECK(n00b_result_is_ok(port_r));
    CHECK(n00b_result_get(port_r) != 0);
    return n00b_result_get(port_r);
}

static void
stop_true(n00b_rocs_service_t *service)
{
    auto stop_r = n00b_rocs_service_stop(service);
    CHECK(n00b_result_is_ok(stop_r));
    CHECK(n00b_result_get(stop_r));
}

static n00b_rocs_service_t *
start_local_service(n00b_string_t *prefix)
{
    set_prefixed_env(prefix, r"ROCS_PROFILE", r"service_local");
    set_prefixed_env(prefix, r"ROCS_HTTP_ADDR", r"127.0.0.1:0");
    set_prefixed_env(prefix, r"ROCS_READ_ONLY", r"false");
    set_prefixed_env(prefix, r"ROCS_WRITER_MODE", r"single_writer");

    auto config_r = n00b_rocs_service_config_from_env(.prefix = prefix);
    CHECK(n00b_result_is_ok(config_r));
    n00b_rocs_service_config_t *config = n00b_result_get(config_r);

    auto read_only_r = n00b_rocs_service_config_get_read_only(config);
    CHECK(n00b_result_is_ok(read_only_r));
    CHECK(!n00b_result_get(read_only_r));

    auto store_config_r = n00b_rocs_service_config_get_store_config(config);
    CHECK(n00b_result_is_ok(store_config_r));
    auto profile_r = n00b_store_config_get_profile(
        n00b_result_get(store_config_r));
    CHECK(n00b_result_is_ok(profile_r));
    CHECK(n00b_result_get(profile_r) == N00B_STORE_PROFILE_SERVICE_LOCAL);

    auto start_r = n00b_rocs_service_start(config, service_schema());
    CHECK(n00b_result_is_ok(start_r));
    return n00b_result_get(start_r);
}

static void
test_local_profile_smoke(void)
{
    n00b_rocs_service_t *service =
        start_local_service(r"ROCS_SMOKE_LOCAL_");
    uint16_t port = bound_port(service);

    n00b_http_response_t *resp = http_get(port, r"/healthz/startup");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"started\"");

    resp = http_get(port, r"/healthz/ready");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"ready\"");

    resp = http_get(port, r"/healthz/live");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"alive\"");

    resp = http_post(port,
                     r"/v1/query",
                     r"{\"filter\":{\"exists\":\"id\"},\"limit\":10}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":0");

    resp = http_post(port,
                     r"/v1/records",
                     r"{\"id\":1,\"message\":\"alpha smoke\"}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"ok\":true");

    resp = http_post(port,
                     r"/v1/records",
                     r"{\"id\":2,\"message\":\"beta\"}");
    CHECK(n00b_http_response_status(resp) == 200);

    resp = http_post(port, r"/v1/flush", r"{}");
    CHECK(n00b_http_response_status(resp) == 200);

    resp = http_post(port,
                     r"/v1/query",
                     r"{\"filter\":{\"exists\":\"id\"},\"limit\":10}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":2");
    check_body_contains(resp, r"\"score\":0");

    resp = http_post(
        port,
        r"/v1/query",
        r"{\"filter\":{\"contains\":{\"field\":\"message\",\"term\":\"alpha\"}},\"limit\":10}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":1");

    CHECK(n00b_result_is_ok(n00b_rocs_service_set_draining(service, true)));
    resp = http_get(port, r"/healthz/ready");
    CHECK(n00b_http_response_status(resp) == 503);
    check_body_contains(resp, r"\"draining\":true");
    resp = http_get(port, r"/healthz/live");
    CHECK(n00b_http_response_status(resp) == 200);

    stop_true(service);
    auto port_r = n00b_rocs_service_bound_port(service);
    CHECK(n00b_result_is_err(port_r));
    CHECK(n00b_result_get_err(port_r) == N00B_ROCS_SERVICE_ERR_CLOSED);
    n00b_printf("  [PASS] local profile startup, requests, and shutdown");
}

static void
test_invalid_config_fail_fast(void)
{
    n00b_string_t *prefix = r"ROCS_SMOKE_BAD_";
    set_prefixed_env(prefix, r"ROCS_PROFILE", r"service_s3");
    set_prefixed_env(prefix, r"ROCS_S3_PREFIX", r"missing-bucket");

    auto config_r = n00b_rocs_service_config_from_env(.prefix = prefix);
    CHECK(n00b_result_is_err(config_r));
    CHECK(n00b_result_get_err(config_r) == N00B_STORE_ERR_CONFIG);
    n00b_printf("  [PASS] invalid config fails before service start");
}

static int
run_optional_s3_smoke(void)
{
    n00b_string_t *endpoint = n00b_getenv(r"N00B_AWS_S3_ENDPOINT");
    n00b_string_t *bucket   = n00b_getenv(r"N00B_AWS_S3_BUCKET");
    if (string_empty(endpoint) || string_empty(bucket)) {
        return skip(r"N00B_AWS_S3_ENDPOINT/N00B_AWS_S3_BUCKET not set");
    }

    n00b_string_t *region = n00b_getenv(r"N00B_AWS_REGION");
    if (string_empty(region)) {
        region = r"us-east-1";
    }
    n00b_string_t *prefix = n00b_getenv(r"N00B_AWS_S3_PREFIX");
    if (string_empty(prefix)) {
        prefix = r"rocs-wp012-service-smoke/";
    }

    ensure_env(r"AWS_REGION", region);
    ensure_env(r"AWS_DEFAULT_REGION", region);

    n00b_string_t *env_prefix = r"ROCS_SMOKE_S3_";
    set_prefixed_env(env_prefix, r"ROCS_PROFILE", r"service_s3");
    set_prefixed_env(env_prefix, r"ROCS_HTTP_ADDR", r"127.0.0.1:0");
    set_prefixed_env(env_prefix, r"ROCS_S3_ENDPOINT", endpoint);
    set_prefixed_env(env_prefix, r"ROCS_S3_BUCKET", bucket);
    set_prefixed_env(env_prefix, r"ROCS_S3_PREFIX", prefix);
    set_prefixed_env(env_prefix, r"ROCS_AWS_REGION", region);
    set_prefixed_env(env_prefix, r"ROCS_S3_PATH_STYLE", r"true");
    set_prefixed_env(env_prefix, r"ROCS_READ_ONLY", r"false");
    set_prefixed_env(env_prefix, r"ROCS_WRITER_MODE", r"single_writer");

    auto config_r = n00b_rocs_service_config_from_env(.prefix = env_prefix);
    if (n00b_result_is_err(config_r)) {
        return skip(r"S3 service config unavailable");
    }

    auto start_r = n00b_rocs_service_start(n00b_result_get(config_r),
                                           service_schema());
    if (n00b_result_is_err(start_r)) {
        return skip(r"S3 service backend unavailable");
    }

    n00b_rocs_service_t *service = n00b_result_get(start_r);
    uint16_t             port    = bound_port(service);

    n00b_http_response_t *resp = http_get(port, r"/healthz/ready");
    if (n00b_http_response_status(resp) != 200) {
        (void)n00b_rocs_service_stop(service);
        return skip(r"S3 service readiness unavailable");
    }

    resp = http_post(port,
                     r"/v1/records",
                     r"{\"id\":1,\"message\":\"s3 smoke\"}");
    if (n00b_http_response_status(resp) != 200) {
        (void)n00b_rocs_service_stop(service);
        return skip(r"S3 service ingest unavailable");
    }

    resp = http_post(port, r"/v1/flush", r"{}");
    if (n00b_http_response_status(resp) != 200) {
        (void)n00b_rocs_service_stop(service);
        return skip(r"S3 service flush unavailable");
    }

    resp = http_post(port,
                     r"/v1/query",
                     r"{\"filter\":{\"exists\":\"id\"},\"limit\":1}");
    CHECK(n00b_http_response_status(resp) == 200);
    check_body_contains(resp, r"\"count\":1");
    stop_true(service);
    n00b_printf("  [PASS] optional S3/LocalStack service smoke");
    return 0;
}

static int
run_local_smoke(void)
{
    n00b_printf("test_rocs_service_smoke:");
    test_local_profile_smoke();
    test_invalid_config_fail_fast();
    return 0;
}

int
main(int argc, char *argv[])
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    int rc = 0;
    if (argc == 2 && n00b_unicode_str_eq(n00b_string_from_cstr(argv[1]),
                                         r"--s3")) {
        rc = run_optional_s3_smoke();
    }
    else {
        rc = run_local_smoke();
    }

    n00b_shutdown();
    return rc;
}
