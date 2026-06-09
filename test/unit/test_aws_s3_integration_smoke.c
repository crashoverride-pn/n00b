/** @file test/unit/test_aws_s3_integration_smoke.c
 *  Opt-in S3-compatible integration smoke for the AWS-backed VFS backend.
 *
 *  Set N00B_AWS_S3_ENDPOINT and N00B_AWS_S3_BUCKET to run. The bucket must
 *  already exist. LocalStack users should set endpoint to http://localhost:4566
 *  and can use dummy AWS credentials; this test supplies them when absent.
 */

#include "n00b.h"
#include "core/buffer.h"
#include "core/env.h"
#include "core/runtime.h"
#include "conduit/print.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "aws/n00b_aws.h"

#define MULTIPART_PART_SIZE (5 * 1024 * 1024)

#define CHECK(expr)                                                            \
    do {                                                                       \
        n00b_require((expr), "test check failed: " #expr);                    \
    } while (0)

static bool
string_empty(n00b_string_t *s)
{
    return s == nullptr || s->data == nullptr || s->u8_bytes == 0;
}

static int
skip(n00b_string_t *reason)
{
    n00b_printf("[SKIP] [|#|]", reason);
    return 77;
}

static void
ensure_env(n00b_string_t *name, n00b_string_t *value)
{
    if (string_empty(n00b_getenv(name))) {
        CHECK(n00b_putenv(name, value));
    }
}

static void
check_buffer_eq(n00b_buffer_t *buf, n00b_buffer_t *expected)
{
    CHECK(buf != nullptr);
    CHECK(expected != nullptr);
    CHECK(n00b_buffer_len(buf) == n00b_buffer_len(expected));

    size_t len = n00b_buffer_len(buf);
    for (size_t i = 0; i < len; i++) {
        auto actual = n00b_buffer_get_index(buf, (int64_t)i);
        auto want   = n00b_buffer_get_index(expected, (int64_t)i);
        CHECK(n00b_result_is_ok(actual));
        CHECK(n00b_result_is_ok(want));
        CHECK(n00b_result_get(actual) == n00b_result_get(want));
    }
}

static n00b_buffer_t *
make_pattern_buffer(size_t len)
{
    char *data = n00b_alloc_array(char, len);
    for (size_t i = 0; i < len; i++) {
        data[i] = (char)('A' + (i % 23));
    }
    return n00b_buffer_from_bytes(data, (int64_t)len);
}

static void
check_pattern_range(n00b_buffer_t *buf, size_t offset, size_t len)
{
    CHECK(buf != nullptr);
    CHECK(n00b_buffer_len(buf) == len);

    for (size_t i = 0; i < len; i++) {
        auto actual = n00b_buffer_get_index(buf, (int64_t)i);
        CHECK(n00b_result_is_ok(actual));
        CHECK(n00b_result_get(actual) == (uint8_t)('A' + ((offset + i) % 23)));
    }
}

static void
delete_if_present(n00b_vfs_backend_t *be, n00b_string_t *key)
{
    auto del_r = be->ops->del(be->ctx, key);
    if (n00b_result_is_err(del_r)) {
        CHECK(n00b_result_get_err(del_r) == N00B_VFS_ERR_NOT_FOUND);
    }
}

static void
test_object_contract(n00b_vfs_backend_t *be)
{
    n00b_string_t *key  = r"contract-object.bin";
    n00b_buffer_t *body = n00b_buffer_from_cstr("abcdef");

    delete_if_present(be, key);

    auto put_r = be->ops->put_if_absent(be->ctx, key, body);
    CHECK(n00b_result_is_ok(put_r));

    put_r = be->ops->put_if_absent(be->ctx,
                                   key,
                                   n00b_buffer_from_cstr("second"));
    CHECK(n00b_result_is_err(put_r));
    CHECK(n00b_result_get_err(put_r) == N00B_VFS_ERR_EXISTS);

    auto get_r = be->ops->get(be->ctx, key);
    CHECK(n00b_result_is_ok(get_r));
    check_buffer_eq(n00b_result_get(get_r), body);

    auto range_r = be->ops->get_range(be->ctx, key, 2, 3);
    CHECK(n00b_result_is_ok(range_r));
    check_buffer_eq(n00b_result_get(range_r), n00b_buffer_from_cstr("cde"));

    auto stat_r = be->ops->stat(be->ctx, key);
    CHECK(n00b_result_is_ok(stat_r));
    n00b_vfs_obj_stat_t st = n00b_result_get(stat_r);
    CHECK(st.kind == N00B_VFS_OBJ_FILE);
    CHECK(st.size == n00b_buffer_len(body));

    auto list_r = be->ops->list(be->ctx, r"", nullptr, 100);
    CHECK(n00b_result_is_ok(list_r));
    n00b_vfs_list_result_t *list = n00b_result_get(list_r);
    bool found = false;
    for (uint32_t i = 0; i < list->count; i++) {
        if (n00b_unicode_str_eq(list->entries[i].name, key)) {
            found = true;
            CHECK(list->entries[i].size == n00b_buffer_len(body));
        }
    }
    CHECK(found);

    auto del_r = be->ops->del(be->ctx, key);
    CHECK(n00b_result_is_ok(del_r));

    get_r = be->ops->get(be->ctx, key);
    CHECK(n00b_result_is_err(get_r));
    CHECK(n00b_result_get_err(get_r) == N00B_VFS_ERR_NOT_FOUND);

    n00b_print(r"  [PASS] object_contract");
}

static void
test_multipart_contract(n00b_vfs_backend_t *be)
{
    n00b_string_t *key  = r"multipart-object.bin";
    n00b_buffer_t *body = make_pattern_buffer(MULTIPART_PART_SIZE
                                              + 1024 * 1024);

    delete_if_present(be, key);

    auto put_r = be->ops->put(be->ctx, key, body);
    CHECK(n00b_result_is_ok(put_r));

    auto stat_r = be->ops->stat(be->ctx, key);
    CHECK(n00b_result_is_ok(stat_r));
    n00b_vfs_obj_stat_t st = n00b_result_get(stat_r);
    CHECK(st.kind == N00B_VFS_OBJ_FILE);
    CHECK(st.size == n00b_buffer_len(body));

    size_t range_offset = MULTIPART_PART_SIZE - 4;
    auto range_r = be->ops->get_range(be->ctx, key, range_offset, 16);
    CHECK(n00b_result_is_ok(range_r));
    check_pattern_range(n00b_result_get(range_r), range_offset, 16);

    auto del_r = be->ops->del(be->ctx, key);
    CHECK(n00b_result_is_ok(del_r));

    n00b_print(r"  [PASS] multipart_contract");
}

int
main(int argc, char **argv)
{
    n00b_init_simple(argc, argv);

    n00b_string_t *endpoint = n00b_getenv(r"N00B_AWS_S3_ENDPOINT");
    n00b_string_t *bucket   = n00b_getenv(r"N00B_AWS_S3_BUCKET");
    if (string_empty(endpoint) || string_empty(bucket)) {
        return skip(r"N00B_AWS_S3_ENDPOINT/N00B_AWS_S3_BUCKET not set");
    }

    n00b_string_t *region = n00b_getenv(r"N00B_AWS_REGION");
    if (string_empty(region)) {
        region = r"us-east-1";
    }
    ensure_env(r"AWS_ACCESS_KEY_ID", r"test");
    ensure_env(r"AWS_SECRET_ACCESS_KEY", r"test");
    ensure_env(r"AWS_REGION", region);
    ensure_env(r"AWS_DEFAULT_REGION", region);

    n00b_string_t *prefix = n00b_getenv(r"N00B_AWS_S3_PREFIX");
    if (string_empty(prefix)) {
        prefix = r"rocs-wp005-s3-smoke/";
    }

    auto cfg_r =
        n00b_aws_config(region, .endpoint_override = endpoint);
    CHECK(n00b_result_is_ok(cfg_r));
    n00b_aws_config_t *cfg = n00b_result_get(cfg_r);
    CHECK(cfg != nullptr);

    auto be_r = n00b_aws_s3_vfs_backend_new(cfg,
                                            bucket,
                                            .prefix           = prefix,
                                            .force_path_style = true,
                                            .content_type     = r"application/x-n00b-shard");
    CHECK(n00b_result_is_ok(be_r));

    n00b_print(r"Running AWS S3 integration smoke...");
    n00b_vfs_backend_t *be = n00b_result_get(be_r);
    test_object_contract(be);
    n00b_vfs_backend_cleanup(be);

    be_r = n00b_aws_s3_vfs_backend_new(cfg,
                                       bucket,
                                       .prefix              = prefix,
                                       .force_path_style    = true,
                                       .content_type        = r"application/x-n00b-shard",
                                       .multipart_threshold = MULTIPART_PART_SIZE,
                                       .multipart_part_size = MULTIPART_PART_SIZE);
    CHECK(n00b_result_is_ok(be_r));
    be = n00b_result_get(be_r);
    test_multipart_contract(be);
    n00b_vfs_backend_cleanup(be);

    n00b_print(r"All AWS S3 integration smoke tests passed.");
    return 0;
}
