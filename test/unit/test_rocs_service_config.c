/* test/unit/test_rocs_service_config.c - WP-012 Phase 1 config profiles. */

#include <stdint.h>

#include "n00b.h"
#include "core/env.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#include <rocs/n00b_rocs.h>
#include <rocs/service.h>
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

static void
set_prefixed_env(n00b_string_t *prefix,
                 n00b_string_t *key,
                 n00b_string_t *value)
{
    n00b_string_t *full_key = n00b_unicode_str_cat(prefix, key);
    CHECK(n00b_putenv(full_key, value));
}

static n00b_string_t *
get_string_option(n00b_result_t(n00b_option_t(n00b_string_t *)) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_option_t(n00b_string_t *) opt = n00b_result_get(r);
    CHECK(n00b_option_is_set(opt));
    return n00b_option_get(opt);
}

static void
check_string_option_none(n00b_result_t(n00b_option_t(n00b_string_t *)) r)
{
    CHECK(n00b_result_is_ok(r));
    CHECK(!n00b_option_is_set(n00b_result_get(r)));
}

static bool
get_bool_option(n00b_result_t(n00b_option_t(bool)) r)
{
    CHECK(n00b_result_is_ok(r));
    n00b_option_t(bool) opt = n00b_result_get(r);
    CHECK(n00b_option_is_set(opt));
    return n00b_option_get(opt);
}

static void
check_bool_option_none(n00b_result_t(n00b_option_t(bool)) r)
{
    CHECK(n00b_result_is_ok(r));
    CHECK(!n00b_option_is_set(n00b_result_get(r)));
}

static n00b_store_config_t *
config_from_env(n00b_string_t *prefix)
{
    auto r = n00b_store_config_from_env(.prefix = prefix);
    CHECK(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

static void
test_default_profiles(void)
{
    static_assert((N00B_ROCS_CAPABILITIES
                   & N00B_ROCS_CAP_SERVICE_CONFIG_DECLS)
                  != 0);
    CHECK(n00b_unicode_str_eq(n00b_store_err_str(N00B_STORE_ERR_CONFIG),
                              r"CONFIG"));

    auto embedded_r = n00b_store_config_default(
        N00B_STORE_PROFILE_EMBEDDED_LOCAL,
        .name = r"embedded-test");
    CHECK(n00b_result_is_ok(embedded_r));
    n00b_store_config_t *embedded = n00b_result_get(embedded_r);

    auto profile_r = n00b_store_config_get_profile(embedded);
    CHECK(n00b_result_is_ok(profile_r));
    CHECK(n00b_result_get(profile_r) == N00B_STORE_PROFILE_EMBEDDED_LOCAL);
    CHECK(n00b_unicode_str_eq(get_string_option(
                                  n00b_store_config_get_name(embedded)),
                              r"embedded-test"));
    CHECK(n00b_unicode_str_eq(get_string_option(
                                  n00b_store_config_get_root(embedded)),
                              r"/rocs"));

    auto cache_r = n00b_store_config_get_cache_bytes(embedded);
    auto bytes_r = n00b_store_config_get_resident_bytes(embedded);
    auto shards_r = n00b_store_config_get_resident_shards(embedded);
    CHECK(n00b_result_is_ok(cache_r));
    CHECK(n00b_result_is_ok(bytes_r));
    CHECK(n00b_result_is_ok(shards_r));
    CHECK(n00b_result_get(cache_r) > 0);
    CHECK(n00b_result_get(bytes_r) > 0);
    CHECK(n00b_result_get(shards_r) > 0);

    auto s3_r = n00b_store_config_default(N00B_STORE_PROFILE_SERVICE_S3);
    CHECK(n00b_result_is_ok(s3_r));
    n00b_store_config_t *s3 = n00b_result_get(s3_r);
    profile_r = n00b_store_config_get_profile(s3);
    CHECK(n00b_result_is_ok(profile_r));
    CHECK(n00b_result_get(profile_r) == N00B_STORE_PROFILE_SERVICE_S3);
    check_string_option_none(n00b_store_config_get_s3_bucket(s3));
    check_string_option_none(n00b_store_config_get_s3_prefix(s3));
    check_bool_option_none(n00b_store_config_get_s3_path_style(s3));
}

static void
test_env_prefix_and_s3_options(void)
{
    n00b_string_t *prefix = r"ROCS_CFG_A_";
    set_prefixed_env(prefix, r"ROCS_PROFILE", r"service_s3");
    set_prefixed_env(prefix, r"ROCS_NAME", r"svc-a");
    set_prefixed_env(prefix, r"ROCS_S3_BUCKET", r"bucket-a");
    set_prefixed_env(prefix, r"ROCS_S3_PREFIX", r"tenant/a");
    set_prefixed_env(prefix, r"ROCS_SCHEMA", r"schema://inline");
    set_prefixed_env(prefix, r"ROCS_AWS_REGION", r"us-east-1");
    set_prefixed_env(prefix, r"ROCS_S3_ENDPOINT", r"http://127.0.0.1:9000");
    set_prefixed_env(prefix, r"ROCS_S3_PATH_STYLE", r"true");
    set_prefixed_env(prefix, r"ROCS_CACHE_DIR", r"/tmp/rocs-cache-a");
    set_prefixed_env(prefix, r"ROCS_CACHE_BYTES", r"4096");
    set_prefixed_env(prefix, r"ROCS_RESIDENT_BYTES", r"8192");
    set_prefixed_env(prefix, r"ROCS_RESIDENT_SHARDS", r"7");
    set_prefixed_env(prefix, r"ROCS_READ_ONLY", r"true");
    set_prefixed_env(prefix, r"ROCS_WRITER_MODE", r"read_replica");

    n00b_store_config_t *config = config_from_env(prefix);

    auto profile_r = n00b_store_config_get_profile(config);
    CHECK(n00b_result_is_ok(profile_r));
    CHECK(n00b_result_get(profile_r) == N00B_STORE_PROFILE_SERVICE_S3);
    CHECK(n00b_unicode_str_eq(get_string_option(
                                  n00b_store_config_get_name(config)),
                              r"svc-a"));
    CHECK(n00b_unicode_str_eq(get_string_option(
                                  n00b_store_config_get_s3_bucket(config)),
                              r"bucket-a"));
    CHECK(n00b_unicode_str_eq(get_string_option(
                                  n00b_store_config_get_s3_prefix(config)),
                              r"tenant/a"));
    CHECK(n00b_unicode_str_eq(get_string_option(
                                  n00b_store_config_get_schema_source(config)),
                              r"schema://inline"));
    CHECK(n00b_unicode_str_eq(get_string_option(
                                  n00b_store_config_get_aws_region(config)),
                              r"us-east-1"));
    CHECK(n00b_unicode_str_eq(get_string_option(
                                  n00b_store_config_get_s3_endpoint(config)),
                              r"http://127.0.0.1:9000"));
    CHECK(get_bool_option(n00b_store_config_get_s3_path_style(config)));
    CHECK(n00b_unicode_str_eq(get_string_option(
                                  n00b_store_config_get_cache_dir(config)),
                              r"/tmp/rocs-cache-a"));

    auto cache_r = n00b_store_config_get_cache_bytes(config);
    auto bytes_r = n00b_store_config_get_resident_bytes(config);
    auto shards_r = n00b_store_config_get_resident_shards(config);
    CHECK(n00b_result_is_ok(cache_r));
    CHECK(n00b_result_is_ok(bytes_r));
    CHECK(n00b_result_is_ok(shards_r));
    CHECK(n00b_result_get(cache_r) == 4096);
    CHECK(n00b_result_get(bytes_r) == 8192);
    CHECK(n00b_result_get(shards_r) == 7);

    auto ro_r = n00b_store_config_get_read_only(config);
    CHECK(n00b_result_is_ok(ro_r));
    CHECK(n00b_result_get(ro_r));
    auto mode_r = n00b_store_config_get_writer_mode(config);
    CHECK(n00b_result_is_ok(mode_r));
    CHECK(n00b_result_get(mode_r) == N00B_STORE_WRITER_READ_REPLICA);
}

static void
expect_env_config_error(n00b_string_t *prefix)
{
    auto r = n00b_store_config_from_env(.prefix = prefix);
    CHECK(n00b_result_is_err(r));
    CHECK(n00b_result_get_err(r) == N00B_STORE_ERR_CONFIG);
}

static void
test_invalid_env_inputs(void)
{
    n00b_string_t *numeric = r"ROCS_CFG_BAD_NUM_";
    set_prefixed_env(numeric, r"ROCS_CACHE_BYTES", r"many");
    expect_env_config_error(numeric);

    n00b_string_t *read_only = r"ROCS_CFG_BAD_BOOL_";
    set_prefixed_env(read_only, r"ROCS_READ_ONLY", r"maybe");
    expect_env_config_error(read_only);

    n00b_string_t *path_style = r"ROCS_CFG_BAD_PATH_STYLE_";
    set_prefixed_env(path_style, r"ROCS_PROFILE", r"service_s3");
    set_prefixed_env(path_style, r"ROCS_S3_BUCKET", r"bucket");
    set_prefixed_env(path_style, r"ROCS_S3_PREFIX", r"prefix");
    set_prefixed_env(path_style, r"ROCS_S3_PATH_STYLE", r"sometimes");
    expect_env_config_error(path_style);

    n00b_string_t *endpoint = r"ROCS_CFG_BAD_ENDPOINT_";
    set_prefixed_env(endpoint, r"ROCS_PROFILE", r"service_s3");
    set_prefixed_env(endpoint, r"ROCS_S3_BUCKET", r"bucket");
    set_prefixed_env(endpoint, r"ROCS_S3_PREFIX", r"prefix");
    set_prefixed_env(endpoint, r"ROCS_S3_ENDPOINT", r"localhost:9000");
    expect_env_config_error(endpoint);

    n00b_string_t *writer = r"ROCS_CFG_BAD_WRITER_";
    set_prefixed_env(writer, r"ROCS_WRITER_MODE", r"multi");
    expect_env_config_error(writer);

    n00b_string_t *incompatible = r"ROCS_CFG_BAD_INCOMPAT_";
    set_prefixed_env(incompatible, r"ROCS_PROFILE", r"service_local");
    set_prefixed_env(incompatible, r"ROCS_S3_BUCKET", r"bucket");
    expect_env_config_error(incompatible);

    n00b_string_t *s3_missing = r"ROCS_CFG_BAD_S3_MISSING_";
    set_prefixed_env(s3_missing, r"ROCS_PROFILE", r"service_s3");
    set_prefixed_env(s3_missing, r"ROCS_S3_PREFIX", r"prefix");
    expect_env_config_error(s3_missing);
}

static void
test_open_config_local_and_s3_validation(void)
{
    auto embedded_r = n00b_store_config_default(
        N00B_STORE_PROFILE_EMBEDDED_LOCAL);
    CHECK(n00b_result_is_ok(embedded_r));
    auto store_r = n00b_store_open_config(new_schema(),
                                          n00b_result_get(embedded_r));
    CHECK(n00b_result_is_ok(store_r));
    CHECK(n00b_result_is_ok(n00b_store_close(n00b_result_get(store_r))));

    auto local_r = n00b_store_config_default(N00B_STORE_PROFILE_SERVICE_LOCAL);
    CHECK(n00b_result_is_ok(local_r));
    store_r = n00b_store_open_config(new_schema(), n00b_result_get(local_r));
    CHECK(n00b_result_is_ok(store_r));
    CHECK(n00b_result_is_ok(n00b_store_close(n00b_result_get(store_r))));

    auto s3_r = n00b_store_config_default(N00B_STORE_PROFILE_SERVICE_S3);
    CHECK(n00b_result_is_ok(s3_r));
    auto missing_r = n00b_store_open_config(new_schema(),
                                            n00b_result_get(s3_r));
    CHECK(n00b_result_is_err(missing_r));
    CHECK(n00b_result_get_err(missing_r) == N00B_STORE_ERR_CONFIG);

    CHECK(n00b_result_is_ok(n00b_store_config_set_s3(n00b_result_get(s3_r),
                                                     r"bucket",
                                                     r"prefix")));
    auto s3_open_r = n00b_store_open_config(new_schema(),
                                            n00b_result_get(s3_r));
    CHECK(n00b_result_is_err(s3_open_r));
    CHECK(n00b_result_get_err(s3_open_r) == N00B_STORE_ERR_VFS);
}

static void
test_service_config_from_env(void)
{
    n00b_string_t *prefix = r"ROCS_SVC_A_";
    set_prefixed_env(prefix, r"ROCS_PROFILE", r"service_local");
    set_prefixed_env(prefix, r"ROCS_HTTP_ADDR", r"0.0.0.0:8081");
    set_prefixed_env(prefix, r"ROCS_READ_ONLY", r"true");

    auto service_r = n00b_rocs_service_config_from_env(.prefix = prefix);
    CHECK(n00b_result_is_ok(service_r));
    n00b_rocs_service_config_t *service = n00b_result_get(service_r);

    CHECK(n00b_unicode_str_eq(get_string_option(
                                  n00b_rocs_service_config_get_http_addr(service)),
                              r"0.0.0.0:8081"));
    auto read_only_r = n00b_rocs_service_config_get_read_only(service);
    CHECK(n00b_result_is_ok(read_only_r));
    CHECK(n00b_result_get(read_only_r));

    auto store_config_r = n00b_rocs_service_config_get_store_config(service);
    CHECK(n00b_result_is_ok(store_config_r));
    auto profile_r = n00b_store_config_get_profile(n00b_result_get(store_config_r));
    CHECK(n00b_result_is_ok(profile_r));
    CHECK(n00b_result_get(profile_r) == N00B_STORE_PROFILE_SERVICE_LOCAL);
    auto mode_r = n00b_store_config_get_writer_mode(n00b_result_get(store_config_r));
    CHECK(n00b_result_is_ok(mode_r));
    CHECK(n00b_result_get(mode_r) == N00B_STORE_WRITER_READ_REPLICA);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_default_profiles();
    test_env_prefix_and_s3_options();
    test_invalid_env_inputs();
    test_open_config_local_and_s3_validation();
    test_service_config_from_env();

    n00b_shutdown();
    return 0;
}
