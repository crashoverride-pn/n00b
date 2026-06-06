#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "compiler/objfile/sink.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "util/path.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#define N00B_TEST_REQUIRE(expr) n00b_require((expr), #expr)

static n00b_objfile_sink_error_t *
require_sink_error(n00b_result_t(n00b_objfile_sink_result_t *) result,
                   n00b_objfile_sink_error_code_t              expected)
{
    N00B_TEST_REQUIRE(n00b_result_is_err(result));
    N00B_TEST_REQUIRE(
        n00b_result_is_err_payload(n00b_objfile_sink_error_t *, result));

    n00b_objfile_sink_error_t *error =
        n00b_result_get_err_payload(n00b_objfile_sink_error_t *, result);

    N00B_TEST_REQUIRE(n00b_objfile_sink_error_code(error) == expected);
    return error;
}

static void
assert_no_destination(n00b_objfile_sink_error_t *error)
{
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_objfile_sink_error_destination_path(error)));
}

static void
assert_destination(n00b_objfile_sink_error_t *error,
                   n00b_string_t             *expected)
{
    auto path = n00b_objfile_sink_error_destination_path(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(path));
    N00B_TEST_REQUIRE(n00b_unicode_str_eq(n00b_option_get(path), expected));
}

static void
assert_request_context(n00b_objfile_sink_error_t    *error,
                       n00b_objfile_sink_mode_t      expected_mode,
                       n00b_objfile_sink_overwrite_t expected_overwrite)
{
    auto mode = n00b_objfile_sink_error_mode(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(mode));
    N00B_TEST_REQUIRE(n00b_option_get(mode) == expected_mode);

    auto overwrite = n00b_objfile_sink_error_overwrite(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(overwrite));
    N00B_TEST_REQUIRE(n00b_option_get(overwrite) == expected_overwrite);
}

static n00b_objfile_sink_result_t *
require_sink_ok(n00b_result_t(n00b_objfile_sink_result_t *) result)
{
    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    n00b_objfile_sink_result_t *facts = n00b_result_get(result);
    N00B_TEST_REQUIRE(facts != nullptr);
    return facts;
}

static n00b_objfile_sink_result_t *
require_error_facts(n00b_objfile_sink_error_t *error)
{
    auto facts = n00b_objfile_sink_error_result_facts(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(facts));
    return n00b_option_get(facts);
}

static n00b_string_t *
fixture_dir(void)
{
    auto dir_r = n00b_new_temp_dir(r"n00b_sink_", r"_dir");

    N00B_TEST_REQUIRE(n00b_result_is_ok(dir_r));
    return n00b_result_get(dir_r);
}

static n00b_string_t *
fixture_child(n00b_string_t *dir, n00b_string_t *name)
{
    return n00b_path_simple_join(dir, name);
}

static n00b_buffer_t *
fixture_buffer(n00b_string_t *contents)
{
    return n00b_buffer_from_bytes(contents->data, (int64_t)contents->u8_bytes);
}

static void
fixture_write(n00b_string_t *path, n00b_string_t *contents)
{
    auto open_r = n00b_file_open(path, .mode = N00B_FILE_W);
    N00B_TEST_REQUIRE(n00b_result_is_ok(open_r));
    n00b_file_t *file = n00b_result_get(open_r);

    auto write_r = n00b_file_write_all(file, fixture_buffer(contents));
    N00B_TEST_REQUIRE(n00b_result_is_ok(write_r));
    N00B_TEST_REQUIRE(n00b_result_get(write_r) == contents->u8_bytes);

    auto close_r = n00b_file_close_result(file);
    N00B_TEST_REQUIRE(n00b_result_is_ok(close_r));
}

static void
fixture_assert_bytes(n00b_string_t *path, n00b_string_t *expected)
{
    auto open_r = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    N00B_TEST_REQUIRE(n00b_result_is_ok(open_r));
    n00b_file_t *file = n00b_result_get(open_r);

    auto buffer_r = n00b_file_as_buffer(file);
    N00B_TEST_REQUIRE(n00b_result_is_ok(buffer_r));
    n00b_buffer_t *buffer = n00b_result_get(buffer_r);

    N00B_TEST_REQUIRE(buffer->byte_len == expected->u8_bytes);
    if (expected->u8_bytes != 0) {
        N00B_TEST_REQUIRE(memcmp(buffer->data,
                                 expected->data,
                                 expected->u8_bytes) == 0);
    }

    n00b_file_close(file);
}

static void
fixture_unlink(n00b_string_t *path)
{
    auto unlink_r = n00b_file_unlink(path, .ignore_missing = true);

    N00B_TEST_REQUIRE(n00b_result_is_ok(unlink_r));
}

static void
fixture_rmdir(n00b_string_t *path)
{
    N00B_TEST_REQUIRE(rmdir(path->data) == 0);
}

static void
test_null_buffer_error(void)
{
    n00b_string_t *path = r"/tmp/n00b-no-side-effect";
    auto result = n00b_objfile_sink_write(nullptr, path);

    n00b_objfile_sink_error_t *error =
        require_sink_error(result, N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT);

    assert_destination(error, path);
    N00B_TEST_REQUIRE(n00b_option_is_set(
        n00b_objfile_sink_error_message(error)));
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_objfile_sink_error_temp_path(error)));
}

static void
test_null_destination_error(void)
{
    n00b_buffer_t *bytes  = n00b_buffer_from_cstr("object");
    auto           result = n00b_objfile_sink_write(bytes, nullptr);

    n00b_objfile_sink_error_t *error =
        require_sink_error(result, N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT);

    assert_no_destination(error);
}

static void
test_empty_destination_error(void)
{
    n00b_buffer_t *bytes  = n00b_buffer_from_cstr("object");
    auto           result = n00b_objfile_sink_write(bytes, r"");

    n00b_objfile_sink_error_t *error =
        require_sink_error(result, N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT);

    assert_no_destination(error);
}

static void
test_invalid_mode_error(void)
{
    n00b_buffer_t *bytes = n00b_buffer_from_cstr("object");
    n00b_string_t *path  = r"/tmp/n00b-no-side-effect";
    auto result = n00b_objfile_sink_write(
        bytes,
        path,
        .sink_mode = (n00b_objfile_sink_mode_t)99);

    n00b_objfile_sink_error_t *error =
        require_sink_error(result, N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT);

    assert_destination(error, path);
    assert_request_context(error,
                           (n00b_objfile_sink_mode_t)99,
                           N00B_OBJFILE_SINK_REJECT_EXISTING);

    auto detail = n00b_objfile_sink_error_detail(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(detail));
    N00B_TEST_REQUIRE(n00b_option_get(detail) == 99);
}

static void
test_invalid_overwrite_error(void)
{
    n00b_buffer_t *bytes = n00b_buffer_from_cstr("object");
    n00b_string_t *path  = r"/tmp/n00b-no-side-effect";
    auto result = n00b_objfile_sink_write(
        bytes,
        path,
        .overwrite = (n00b_objfile_sink_overwrite_t)99);

    n00b_objfile_sink_error_t *error =
        require_sink_error(result, N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT);

    assert_destination(error, path);
    assert_request_context(error,
                           N00B_OBJFILE_SINK_MODE_ATOMIC,
                           (n00b_objfile_sink_overwrite_t)99);
}

static void
test_invalid_file_mode_error(void)
{
    n00b_buffer_t *bytes = n00b_buffer_from_cstr("object");
    n00b_string_t *path  = r"/tmp/n00b-no-side-effect";
    auto result = n00b_objfile_sink_write(
        bytes,
        path,
        .file_mode = n00b_option_set(uint32_t, 010000u));

    n00b_objfile_sink_error_t *error =
        require_sink_error(result, N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT);

    assert_destination(error, path);
    assert_request_context(error,
                           N00B_OBJFILE_SINK_MODE_ATOMIC,
                           N00B_OBJFILE_SINK_REJECT_EXISTING);
}

static void
test_error_strings(void)
{
    N00B_TEST_REQUIRE(n00b_objfile_sink_err_str(
                          N00B_OBJFILE_SINK_ERR_INVALID_ARGUMENT)
                      != nullptr);
    N00B_TEST_REQUIRE(n00b_objfile_sink_err_str(
                          N00B_OBJFILE_SINK_ERR_UNSUPPORTED)
                      != nullptr);
    N00B_TEST_REQUIRE(n00b_objfile_sink_err_str(-3999) != nullptr);
}

static void
test_atomic_new_file_write(void)
{
    n00b_string_t *dir  = fixture_dir();
    n00b_string_t *path = fixture_child(dir, r"artifact.o");
    n00b_buffer_t *bytes = fixture_buffer(r"new object bytes");

    n00b_objfile_sink_result_t *facts =
        require_sink_ok(n00b_objfile_sink_write(bytes, path));

    N00B_TEST_REQUIRE(n00b_unicode_str_eq(
        n00b_objfile_sink_result_destination_path(facts), path));
    N00B_TEST_REQUIRE(
        n00b_objfile_sink_result_bytes_requested(facts) == bytes->byte_len);
    N00B_TEST_REQUIRE(
        n00b_objfile_sink_result_bytes_written(facts) == bytes->byte_len);
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_mode_requested(facts)
                      == N00B_OBJFILE_SINK_MODE_ATOMIC);
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_mode_used(facts)
                      == N00B_OBJFILE_SINK_MODE_ATOMIC);
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_overwrite(facts)
                      == N00B_OBJFILE_SINK_REJECT_EXISTING);
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_commit_attempted(facts));
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_commit_completed(facts));
    N00B_TEST_REQUIRE(!n00b_objfile_sink_result_cleanup_attempted(facts));
    N00B_TEST_REQUIRE(!n00b_objfile_sink_result_rollback_attempted(facts));

    auto temp = n00b_objfile_sink_result_temp_path(facts);
    N00B_TEST_REQUIRE(n00b_option_is_set(temp));
    N00B_TEST_REQUIRE(!n00b_path_exists(n00b_option_get(temp)));

    fixture_assert_bytes(path, r"new object bytes");
    fixture_unlink(path);
    fixture_rmdir(dir);
}

static void
test_atomic_overwrite_rejection(void)
{
    n00b_string_t *dir  = fixture_dir();
    n00b_string_t *path = fixture_child(dir, r"artifact.o");
    fixture_write(path, r"original");

    auto result = n00b_objfile_sink_write(fixture_buffer(r"replacement"),
                                          path);

    N00B_TEST_REQUIRE(n00b_result_is_err(result));
    N00B_TEST_REQUIRE(
        n00b_result_is_err_payload(n00b_objfile_sink_error_t *, result));
    n00b_objfile_sink_error_t *error =
        n00b_result_get_err_payload(n00b_objfile_sink_error_t *, result);
    n00b_objfile_sink_error_code_t code =
        n00b_objfile_sink_error_code(error);

    N00B_TEST_REQUIRE(code == N00B_OBJFILE_SINK_ERR_COMMIT_FAILED
                      || code == N00B_OBJFILE_SINK_ERR_UNSUPPORTED);
    n00b_objfile_sink_result_t *facts = require_error_facts(error);

    assert_destination(error, path);
    assert_request_context(error,
                           N00B_OBJFILE_SINK_MODE_ATOMIC,
                           N00B_OBJFILE_SINK_REJECT_EXISTING);
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_commit_attempted(facts));
    N00B_TEST_REQUIRE(!n00b_objfile_sink_result_commit_completed(facts));
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_cleanup_attempted(facts));
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_cleanup_succeeded(facts));

    auto temp = n00b_objfile_sink_result_temp_path(facts);
    N00B_TEST_REQUIRE(n00b_option_is_set(temp));
    N00B_TEST_REQUIRE(!n00b_path_exists(n00b_option_get(temp)));

    auto detail = n00b_objfile_sink_error_detail(error);
    N00B_TEST_REQUIRE(n00b_option_is_set(detail));
    if (code == N00B_OBJFILE_SINK_ERR_COMMIT_FAILED) {
        N00B_TEST_REQUIRE(n00b_option_get(detail) == EEXIST);
    }
    else {
        N00B_TEST_REQUIRE(n00b_option_get(detail) == ENOSYS);
    }

    fixture_assert_bytes(path, r"original");
    fixture_unlink(path);
    fixture_rmdir(dir);
}

static void
test_atomic_replacement_preserves_mode(void)
{
    n00b_string_t *dir  = fixture_dir();
    n00b_string_t *path = fixture_child(dir, r"artifact.o");
    fixture_write(path, r"old");

    auto set_mode = n00b_path_set_mode(path, 0600u);
    bool can_check_mode = n00b_result_is_ok(set_mode);
    uint32_t original_mode = can_check_mode ? n00b_result_get(set_mode) : 0;

    n00b_objfile_sink_result_t *facts = require_sink_ok(
        n00b_objfile_sink_write(fixture_buffer(r"new"),
                                path,
                                .overwrite =
                                    N00B_OBJFILE_SINK_REPLACE_EXISTING));

    N00B_TEST_REQUIRE(n00b_objfile_sink_result_commit_attempted(facts));
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_commit_completed(facts));
    fixture_assert_bytes(path, r"new");

    if (can_check_mode
        && n00b_objfile_sink_result_file_mode_supported(facts)) {
        auto requested =
            n00b_objfile_sink_result_file_mode_requested(facts);
        auto applied = n00b_objfile_sink_result_file_mode_applied(facts);

        N00B_TEST_REQUIRE(n00b_option_is_set(requested));
        N00B_TEST_REQUIRE(n00b_option_is_set(applied));
        N00B_TEST_REQUIRE((n00b_option_get(requested) & 0777u)
                          == (original_mode & 0777u));
        N00B_TEST_REQUIRE((n00b_option_get(applied) & 0777u)
                          == (original_mode & 0777u));
    }

    fixture_unlink(path);
    fixture_rmdir(dir);
}

static void
test_direct_write_where_supported(void)
{
    n00b_string_t *dir  = fixture_dir();
    n00b_string_t *path = fixture_child(dir, r"direct.o");
    auto result = n00b_objfile_sink_write(
        fixture_buffer(r"direct bytes"),
        path,
        .sink_mode = N00B_OBJFILE_SINK_MODE_DIRECT);

    if (n00b_result_is_err(result)) {
        n00b_objfile_sink_error_t *error =
            require_sink_error(result, N00B_OBJFILE_SINK_ERR_UNSUPPORTED);
        assert_destination(error, path);
        fixture_rmdir(dir);
        return;
    }

    n00b_objfile_sink_result_t *facts = n00b_result_get(result);
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_mode_used(facts)
                      == N00B_OBJFILE_SINK_MODE_DIRECT);
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_commit_attempted(facts));
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_commit_completed(facts));
    N00B_TEST_REQUIRE(!n00b_objfile_sink_result_rollback_attempted(facts));
    N00B_TEST_REQUIRE(!n00b_objfile_sink_result_cleanup_attempted(facts));
    fixture_assert_bytes(path, r"direct bytes");
    fixture_unlink(path);
    fixture_rmdir(dir);
}

static void
test_direct_overwrite_rejection(void)
{
    n00b_string_t *dir  = fixture_dir();
    n00b_string_t *path = fixture_child(dir, r"direct-reject.o");
    fixture_write(path, r"original direct contents");

    auto result = n00b_objfile_sink_write(
        fixture_buffer(r"replacement"),
        path,
        .sink_mode = N00B_OBJFILE_SINK_MODE_DIRECT);

    if (n00b_result_is_err(result)) {
        n00b_objfile_sink_error_t *error =
            n00b_result_get_err_payload(n00b_objfile_sink_error_t *, result);
        if (n00b_objfile_sink_error_code(error)
            == N00B_OBJFILE_SINK_ERR_UNSUPPORTED) {
            assert_destination(error, path);
            fixture_assert_bytes(path, r"original direct contents");
            fixture_unlink(path);
            fixture_rmdir(dir);
            return;
        }
    }

    n00b_objfile_sink_error_t *error =
        require_sink_error(result, N00B_OBJFILE_SINK_ERR_COMMIT_FAILED);
    n00b_objfile_sink_result_t *facts = require_error_facts(error);

    assert_destination(error, path);
    assert_request_context(error,
                           N00B_OBJFILE_SINK_MODE_DIRECT,
                           N00B_OBJFILE_SINK_REJECT_EXISTING);
    N00B_TEST_REQUIRE(!n00b_objfile_sink_result_commit_attempted(facts));
    N00B_TEST_REQUIRE(!n00b_objfile_sink_result_commit_completed(facts));

    auto detail = n00b_objfile_sink_error_detail(error);
    N00B_TEST_REQUIRE(n00b_option_is_set(detail));
    N00B_TEST_REQUIRE(n00b_option_get(detail) == EEXIST);

    fixture_assert_bytes(path, r"original direct contents");
    fixture_unlink(path);
    fixture_rmdir(dir);
}

static void
test_direct_replacement_truncates_existing(void)
{
    n00b_string_t *dir  = fixture_dir();
    n00b_string_t *path = fixture_child(dir, r"direct-replace.o");
    fixture_write(path, r"long existing contents");

    auto result = n00b_objfile_sink_write(
        fixture_buffer(r"short"),
        path,
        .sink_mode = N00B_OBJFILE_SINK_MODE_DIRECT,
        .overwrite = N00B_OBJFILE_SINK_REPLACE_EXISTING);

    if (n00b_result_is_err(result)) {
        n00b_objfile_sink_error_t *error =
            require_sink_error(result, N00B_OBJFILE_SINK_ERR_UNSUPPORTED);
        assert_destination(error, path);
        fixture_unlink(path);
        fixture_rmdir(dir);
        return;
    }

    n00b_objfile_sink_result_t *facts = n00b_result_get(result);
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_mode_used(facts)
                      == N00B_OBJFILE_SINK_MODE_DIRECT);
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_overwrite(facts)
                      == N00B_OBJFILE_SINK_REPLACE_EXISTING);
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_commit_attempted(facts));
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_commit_completed(facts));
    fixture_assert_bytes(path, r"short");
    fixture_unlink(path);
    fixture_rmdir(dir);
}

static void
test_atomic_commit_failure_cleans_temp(void)
{
    n00b_string_t *destination_dir = fixture_dir();
    auto result = n00b_objfile_sink_write(
        fixture_buffer(r"cannot replace a directory"),
        destination_dir,
        .overwrite = N00B_OBJFILE_SINK_REPLACE_EXISTING);

    n00b_objfile_sink_error_t *error =
        require_sink_error(result, N00B_OBJFILE_SINK_ERR_COMMIT_FAILED);
    n00b_objfile_sink_result_t *facts = require_error_facts(error);

    N00B_TEST_REQUIRE(n00b_objfile_sink_result_commit_attempted(facts));
    N00B_TEST_REQUIRE(!n00b_objfile_sink_result_commit_completed(facts));
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_cleanup_attempted(facts));
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_cleanup_succeeded(facts));
    N00B_TEST_REQUIRE(!n00b_objfile_sink_result_rollback_attempted(facts));
    N00B_TEST_REQUIRE(!n00b_objfile_sink_result_rollback_succeeded(facts));

    auto temp = n00b_objfile_sink_error_temp_path(error);
    N00B_TEST_REQUIRE(n00b_option_is_set(temp));
    N00B_TEST_REQUIRE(!n00b_path_exists(n00b_option_get(temp)));
    N00B_TEST_REQUIRE(n00b_path_is_directory(destination_dir));
    fixture_rmdir(destination_dir);
}

static void
test_zero_length_atomic_write(void)
{
    n00b_string_t *dir  = fixture_dir();
    n00b_string_t *path = fixture_child(dir, r"empty.o");
    n00b_buffer_t *bytes = n00b_buffer_from_bytes("", 0);

    n00b_objfile_sink_result_t *facts =
        require_sink_ok(n00b_objfile_sink_write(bytes, path));

    N00B_TEST_REQUIRE(
        n00b_objfile_sink_result_bytes_requested(facts) == 0);
    N00B_TEST_REQUIRE(n00b_objfile_sink_result_bytes_written(facts) == 0);
    fixture_assert_bytes(path, r"");
    fixture_unlink(path);
    fixture_rmdir(dir);
}

static void
test_explicit_file_mode(void)
{
    n00b_string_t *dir  = fixture_dir();
    n00b_string_t *path = fixture_child(dir, r"mode.o");

    n00b_objfile_sink_result_t *facts = require_sink_ok(
        n00b_objfile_sink_write(fixture_buffer(r"mode bytes"),
                                path,
                                .file_mode = n00b_option_set(uint32_t,
                                                              0640u),
                                .preserve_existing_mode = false));

    auto requested = n00b_objfile_sink_result_file_mode_requested(facts);
    N00B_TEST_REQUIRE(n00b_option_is_set(requested));
    N00B_TEST_REQUIRE(n00b_option_get(requested) == 0640u);

    if (n00b_objfile_sink_result_file_mode_supported(facts)) {
        auto applied = n00b_objfile_sink_result_file_mode_applied(facts);
        N00B_TEST_REQUIRE(n00b_option_is_set(applied));
        N00B_TEST_REQUIRE((n00b_option_get(applied) & 0777u) == 0640u);

        auto path_mode = n00b_path_get_mode(path);
        N00B_TEST_REQUIRE(n00b_result_is_ok(path_mode));
        N00B_TEST_REQUIRE((n00b_result_get(path_mode) & 0777u) == 0640u);
    }

    fixture_assert_bytes(path, r"mode bytes");
    fixture_unlink(path);
    fixture_rmdir(dir);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_null_buffer_error();
    test_null_destination_error();
    test_empty_destination_error();
    test_invalid_mode_error();
    test_invalid_overwrite_error();
    test_invalid_file_mode_error();
    test_error_strings();
    test_atomic_new_file_write();
    test_atomic_overwrite_rejection();
    test_atomic_replacement_preserves_mode();
    test_direct_write_where_supported();
    test_direct_overwrite_rejection();
    test_direct_replacement_truncates_existing();
    test_atomic_commit_failure_cleans_temp();
    test_zero_length_atomic_write();
    test_explicit_file_mode();

    return 0;
}
