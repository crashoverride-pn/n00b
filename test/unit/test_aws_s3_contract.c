/** @file test/unit/test_aws_s3_contract.c
 *  No-network binding contract for libn00b_aws S3.
 */


#include "n00b.h"
#include "core/buffer.h"
#include "core/env.h"
#include "core/runtime.h"
#include "core/string.h"
#include "conduit/print.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "aws/n00b_aws.h"
#include "internal/aws/s3_test.h"
#include "vfs/types.h"

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
ensure_env(n00b_string_t *name, n00b_string_t *value)
{
    if (string_empty(n00b_getenv(name))) {
        CHECK(n00b_putenv(name, value));
    }
}

static bool
str_eq_c(n00b_string_t *s, const char *c)
{
    return n00b_unicode_str_eq(s, n00b_string_from_cstr(c));
}

static void
test_invalid_args(void)
{
    auto client_r = n00b_aws_s3_client_new(nullptr);
    CHECK(n00b_result_is_err(client_r));
    CHECK(n00b_result_get_err(client_r) == N00B_AWS_ERR_INVALID_ARG);

    auto get_r = n00b_aws_s3_get_object(nullptr, r"bucket", r"key");
    CHECK(n00b_result_is_err(get_r));
    CHECK(n00b_result_get_err(get_r) == N00B_AWS_ERR_INVALID_ARG);

    auto range_r =
        n00b_aws_s3_get_object_range(nullptr, r"bucket", r"key", 0, 1);
    CHECK(n00b_result_is_err(range_r));
    CHECK(n00b_result_get_err(range_r) == N00B_AWS_ERR_INVALID_ARG);

    auto put_status =
        n00b_aws_s3_put_object(nullptr,
                               r"bucket",
                               r"key",
                               n00b_buffer_from_cstr("body"));
    CHECK(n00b_result_is_err(put_status));
    CHECK(n00b_result_get_err(put_status) == N00B_AWS_ERR_INVALID_ARG);

    put_status =
        n00b_aws_s3_put_object_if_absent(nullptr,
                                         r"bucket",
                                         r"key",
                                         n00b_buffer_from_cstr("body"));
    CHECK(n00b_result_is_err(put_status));
    CHECK(n00b_result_get_err(put_status) == N00B_AWS_ERR_INVALID_ARG);

    put_status =
        n00b_aws_s3_put_object_multipart(nullptr,
                                         r"bucket",
                                         r"key",
                                         n00b_buffer_from_cstr("body"));
    CHECK(n00b_result_is_err(put_status));
    CHECK(n00b_result_get_err(put_status) == N00B_AWS_ERR_INVALID_ARG);

    auto multipart_r =
        n00b_aws_s3_multipart_create(nullptr, r"bucket", r"key");
    CHECK(n00b_result_is_err(multipart_r));
    CHECK(n00b_result_get_err(multipart_r) == N00B_AWS_ERR_INVALID_ARG);

    auto part_r =
        n00b_aws_s3_multipart_upload_part(nullptr,
                                          r"bucket",
                                          r"key",
                                          r"upload",
                                          1,
                                          n00b_buffer_from_cstr("body"));
    CHECK(n00b_result_is_err(part_r));
    CHECK(n00b_result_get_err(part_r) == N00B_AWS_ERR_INVALID_ARG);

    n00b_aws_s3_completed_part_t parts[1] = {
        {.part_number = 1, .etag = r"etag"},
    };
    auto mp_status =
        n00b_aws_s3_multipart_complete(nullptr,
                                       r"bucket",
                                       r"key",
                                       r"upload",
                                       parts,
                                       1);
    CHECK(n00b_result_is_err(mp_status));
    CHECK(n00b_result_get_err(mp_status) == N00B_AWS_ERR_INVALID_ARG);

    mp_status =
        n00b_aws_s3_multipart_abort(nullptr, r"bucket", r"key", r"upload");
    CHECK(n00b_result_is_err(mp_status));
    CHECK(n00b_result_get_err(mp_status) == N00B_AWS_ERR_INVALID_ARG);

    auto del_status =
        n00b_aws_s3_delete_object(nullptr, r"bucket", r"key");
    CHECK(n00b_result_is_err(del_status));
    CHECK(n00b_result_get_err(del_status) == N00B_AWS_ERR_INVALID_ARG);

    auto head_r = n00b_aws_s3_head_object(nullptr, r"bucket", r"key");
    CHECK(n00b_result_is_err(head_r));
    CHECK(n00b_result_get_err(head_r) == N00B_AWS_ERR_INVALID_ARG);

    auto list_r = n00b_aws_s3_list_objects(nullptr, r"bucket", r"prefix");
    CHECK(n00b_result_is_err(list_r));
    CHECK(n00b_result_get_err(list_r) == N00B_AWS_ERR_INVALID_ARG);

    auto vfs_client_r = n00b_aws_s3_vfs_client_new(nullptr);
    CHECK(n00b_result_is_err(vfs_client_r));
    CHECK(n00b_result_get_err(vfs_client_r) == N00B_VFS_ERR_NULL_ARG);

    auto vfs_backend_r = n00b_aws_s3_vfs_backend_new(nullptr, r"bucket");
    CHECK(n00b_result_is_err(vfs_backend_r));
    CHECK(n00b_result_get_err(vfs_backend_r) == N00B_VFS_ERR_NULL_ARG);

    n00b_print(r"  [PASS] invalid_args");
}

static void
test_raw_conversion_and_error_mapping(void)
{
    uint8_t raw_body[3] = {1, 2, 3};
    n00b_aws_s3_object_t *obj =
        n00b_aws_s3_test_object_from_raw(raw_body,
                                         sizeof(raw_body),
                                         sizeof(raw_body),
                                         123,
                                         "etag-1",
                                         "application/test",
                                         nullptr);
    CHECK(obj != nullptr);
    CHECK(obj->body != nullptr);
    CHECK(obj->size == 3);
    CHECK(obj->last_modified_ms == 123);
    CHECK(str_eq_c(obj->etag, "etag-1"));
    CHECK(str_eq_c(obj->content_type, "application/test"));

    raw_body[0] = 9;
    auto byte_r = n00b_buffer_get_index(obj->body, 0);
    CHECK(n00b_result_is_ok(byte_r));
    CHECK(n00b_result_get(byte_r) == 1);

    n00b_aws_s3_stat_t *st =
        n00b_aws_s3_test_stat_from_raw(77,
                                       -1,
                                       nullptr,
                                       "application/stat",
                                       nullptr);
    CHECK(st != nullptr);
    CHECK(st->size == 77);
    CHECK(st->last_modified_ms == 0);
    CHECK(str_eq_c(st->etag, ""));
    CHECK(str_eq_c(st->content_type, "application/stat"));

    n00b_aws_s3_list_result_t *list =
        n00b_aws_s3_test_list_from_raw(nullptr);
    CHECK(list != nullptr);
    CHECK(list->count == 2);
    CHECK(list->truncated);
    CHECK(str_eq_c(list->continuation, "next-token"));
    CHECK(str_eq_c(list->entries[0].key, "alpha.bin"));
    CHECK(list->entries[0].size == 5);
    CHECK(list->entries[0].last_modified_ms == 17);
    CHECK(str_eq_c(list->entries[0].etag, "etag-a"));
    CHECK(str_eq_c(list->entries[1].key, "nested/beta.bin"));
    CHECK(list->entries[1].size == 9);
    CHECK(list->entries[1].last_modified_ms == 0);
    CHECK(str_eq_c(list->entries[1].etag, ""));

    CHECK(n00b_aws_s3_test_vfs_error(N00B_AWS_ERR_NOT_FOUND)
          == N00B_VFS_ERR_NOT_FOUND);
    CHECK(n00b_aws_s3_test_vfs_error(N00B_AWS_ERR_EXISTS)
          == N00B_VFS_ERR_EXISTS);
    CHECK(n00b_aws_s3_test_vfs_error(N00B_AWS_ERR_AUTHZ)
          == N00B_VFS_ERR_PERMISSION);
    CHECK(n00b_aws_s3_test_vfs_error(N00B_AWS_ERR_NETWORK)
          == N00B_VFS_ERR_IO);

    n00b_print(r"  [PASS] raw_conversion_and_error_mapping");
}

static void
test_empty_multipart_rejected_before_upload(void)
{
    ensure_env(r"AWS_ACCESS_KEY_ID", r"test");
    ensure_env(r"AWS_SECRET_ACCESS_KEY", r"test");
    ensure_env(r"AWS_REGION", r"us-east-1");
    ensure_env(r"AWS_DEFAULT_REGION", r"us-east-1");

    auto cfg_r =
        n00b_aws_config(r"us-east-1",
                        .endpoint_override = r"http://127.0.0.1:9");
    CHECK(n00b_result_is_ok(cfg_r));
    n00b_aws_config_t *cfg = n00b_result_get(cfg_r);
    CHECK(cfg != nullptr);

    auto client_r = n00b_aws_s3_client_new(cfg, .force_path_style = true);
    CHECK(n00b_result_is_ok(client_r));

    auto status =
        n00b_aws_s3_put_object_multipart(n00b_result_get(client_r),
                                         r"bucket",
                                         r"key",
                                         n00b_buffer_new(0),
                                         .part_size = 5 * 1024 * 1024);
    CHECK(n00b_result_is_err(status));
    CHECK(n00b_result_get_err(status) == N00B_AWS_ERR_INVALID_ARG);

    n00b_print(r"  [PASS] empty_multipart_rejected_before_upload");
}

int
main(int argc, char **argv)
{
    n00b_init_simple(argc, argv);
    n00b_print(r"== libn00b_aws S3 ==");
    test_invalid_args();
    test_raw_conversion_and_error_mapping();
    test_empty_multipart_rejected_before_upload();
    n00b_print(r"All libn00b_aws S3 binding tests passed.");
    return 0;
}
