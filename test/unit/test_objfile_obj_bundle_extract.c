#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "adt/list.h"
#include "compiler/objfile/obj_bundle.h"
#include "core/arena.h"
#include "core/file.h"
#include "core/memory_info.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include "util/path.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#define N00B_TEST_REQUIRE(expr) n00b_require((expr), #expr)

#define TEST_DECL_POLICY_SIZE                 64u
#define TEST_DECL_POLICY_DECL_FLAGS_OFF       16u
#define TEST_DECL_POLICY_PATH_FLAGS_OFF       24u
#define TEST_DECL_POLICY_ARTIFACT_MASK_OFF    32u
#define TEST_DECL_POLICY_EXEC_FLAGS_OFF       40u
#define TEST_DECL_POLICY_FALLBACK_ID_OFF      48u
#define TEST_DECL_POLICY_RESERVED1_OFF        56u
#define TEST_DECL_PATH_DEFAULT                0x1full
#define TEST_DECL_ARTIFACT_KIND_DEFAULT       0x1full
#define TEST_DECL_EXEC_DEFAULT                0x03ull
#define TEST_EMBEDDED_POLICY_COMPAT_FLAGS_OFF 16u
#define TEST_EMBEDDED_POLICY_FALLBACK_ID_OFF  24u
#define TEST_EMBEDDED_POLICY_SOURCE_LEN_OFF   32u

typedef struct test_obj_bundle_exec_mapping {
    n00b_string_t *selector;
    uint64_t       target_artifact_id;
} test_obj_bundle_exec_mapping_t;

typedef struct test_obj_bundle_policy {
    uint64_t                      policy_id;
    n00b_obj_bundle_policy_kind_t kind;
    n00b_obj_bundle_policy_scope_t scope;
    uint64_t                      flags;
    uint64_t                      priority;
    const n00b_buffer_t          *payload;
    uint64_t                      fallback_policy_id;
} test_obj_bundle_policy_t;

typedef struct test_obj_bundle_shadow {
    n00b_allocator_t                              *allocator;
    bool                                          is_mutable;
    uint64_t                                      next_artifact_id;
    n00b_list_t(n00b_obj_bundle_artifact_t *)     artifacts;
    bool                                          has_default_exec;
    uint64_t                                      default_exec_id;
    n00b_list_t(test_obj_bundle_exec_mapping_t *) exec_mappings;
    n00b_list_t(test_obj_bundle_policy_t *)       policies;
} test_obj_bundle_shadow_t;

static n00b_obj_bundle_t *
new_bundle(void)
{
    auto create = n00b_obj_bundle_new();

    N00B_TEST_REQUIRE(n00b_result_is_ok(create));
    return n00b_result_get(create);
}

static n00b_obj_bundle_t *
new_bundle_with_allocator(n00b_allocator_t *allocator)
{
    auto create = n00b_obj_bundle_new(.allocator = allocator);

    N00B_TEST_REQUIRE(n00b_result_is_ok(create));
    return n00b_result_get(create);
}

static test_obj_bundle_policy_t *
test_policy_at(n00b_obj_bundle_t *bundle, size_t index)
{
    test_obj_bundle_shadow_t *shadow = (test_obj_bundle_shadow_t *)bundle;

    N00B_TEST_REQUIRE(index < shadow->policies.len);
    return shadow->policies.data[index];
}

static n00b_buffer_t *
payload_bytes(void)
{
    return n00b_buffer_from_bytes((char *)"payload", 7);
}

static void
write_le16(uint8_t *data, size_t off, uint16_t value)
{
    data[off]     = (uint8_t)value;
    data[off + 1] = (uint8_t)(value >> 8);
}

static void
write_le32(uint8_t *data, size_t off, uint32_t value)
{
    data[off]     = (uint8_t)value;
    data[off + 1] = (uint8_t)(value >> 8);
    data[off + 2] = (uint8_t)(value >> 16);
    data[off + 3] = (uint8_t)(value >> 24);
}

static void
write_le64(uint8_t *data, size_t off, uint64_t value)
{
    write_le32(data, off, (uint32_t)value);
    write_le32(data, off + 4, (uint32_t)(value >> 32));
}

static n00b_buffer_t *
make_policy_payload(uint64_t fallback_policy_id)
{
    uint8_t bytes[TEST_DECL_POLICY_SIZE] = {
        'N', '0', '0', 'B', 'P', 'O', 'L', '1',
    };

    write_le16(bytes, 8, 1);
    write_le16(bytes, 10, 0);
    write_le32(bytes, 12, 0);
    write_le64(bytes, TEST_DECL_POLICY_DECL_FLAGS_OFF, 0);
    write_le64(bytes, TEST_DECL_POLICY_PATH_FLAGS_OFF,
               TEST_DECL_PATH_DEFAULT);
    write_le64(bytes, TEST_DECL_POLICY_ARTIFACT_MASK_OFF,
               TEST_DECL_ARTIFACT_KIND_DEFAULT);
    write_le64(bytes, TEST_DECL_POLICY_EXEC_FLAGS_OFF,
               TEST_DECL_EXEC_DEFAULT);
    write_le64(bytes, TEST_DECL_POLICY_FALLBACK_ID_OFF,
               fallback_policy_id);
    write_le64(bytes, TEST_DECL_POLICY_RESERVED1_OFF, 0);

    return n00b_buffer_from_bytes((char *)bytes,
                                  (int64_t)TEST_DECL_POLICY_SIZE);
}

static n00b_buffer_t *
make_embedded_policy_payload(uint64_t       fallback_policy_id,
                             n00b_string_t *source)
{
    N00B_TEST_REQUIRE(source != nullptr);
    N00B_TEST_REQUIRE(source->data != nullptr);

    size_t len = N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF
                 + source->u8_bytes;
    n00b_buffer_t *payload = n00b_buffer_new((int64_t)len);
    uint8_t       *data    = (uint8_t *)payload->data;

    for (size_t i = 0; i < len; i++) {
        data[i] = 0;
    }

    memcpy(data,
           N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC,
           N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC_LEN);
    write_le16(data, 8, N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAJOR);
    write_le16(data, 10, N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MINOR);
    write_le64(data,
               TEST_EMBEDDED_POLICY_COMPAT_FLAGS_OFF,
               N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SUPPORTED_COMPAT_FLAGS);
    write_le64(data, TEST_EMBEDDED_POLICY_FALLBACK_ID_OFF, fallback_policy_id);
    write_le64(data,
               TEST_EMBEDDED_POLICY_SOURCE_LEN_OFF,
               (uint64_t)source->u8_bytes);
    memcpy(data + N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF,
           source->data,
           source->u8_bytes);

    return payload;
}

static n00b_obj_bundle_error_t *
require_extract_error(n00b_result_t(n00b_obj_bundle_extract_result_t *) result,
                      n00b_obj_bundle_error_code_t expected)
{
    N00B_TEST_REQUIRE(n00b_result_is_err(result));
    N00B_TEST_REQUIRE(
        n00b_result_is_err_payload(n00b_obj_bundle_error_t *, result));

    n00b_obj_bundle_error_t *error =
        n00b_result_get_err_payload(n00b_obj_bundle_error_t *, result);

    N00B_TEST_REQUIRE(n00b_obj_bundle_error_code(error) == expected);
    return error;
}

static n00b_obj_bundle_extract_result_t *
require_extract_ok(n00b_result_t(n00b_obj_bundle_extract_result_t *) result)
{
    N00B_TEST_REQUIRE(n00b_result_is_ok(result));

    n00b_obj_bundle_extract_result_t *facts = n00b_result_get(result);

    N00B_TEST_REQUIRE(facts != nullptr);
    return facts;
}

static void
assert_string_eq(n00b_string_t *actual, n00b_string_t *expected)
{
    N00B_TEST_REQUIRE(n00b_unicode_str_eq(actual, expected));
}

static void
assert_destination(n00b_obj_bundle_error_t *error, n00b_string_t *expected)
{
    auto destination = n00b_obj_bundle_error_destination_path(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(destination));
    assert_string_eq(n00b_option_get(destination), expected);
}

static void
assert_no_destination(n00b_obj_bundle_error_t *error)
{
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_error_destination_path(error)));
}

static n00b_obj_bundle_extract_result_t *
require_extract_facts(n00b_obj_bundle_error_t *error)
{
    auto facts = n00b_obj_bundle_error_extract_result_facts(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(facts));
    return n00b_option_get(facts);
}

static void
assert_no_extract_facts(n00b_obj_bundle_error_t *error)
{
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_error_extract_result_facts(error)));
}

static void
assert_extraction_scope(n00b_obj_bundle_error_t *error)
{
    auto scope = n00b_obj_bundle_error_policy_scope(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(scope));
    N00B_TEST_REQUIRE(n00b_option_get(scope)
                      == N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION);
}

static void
assert_no_side_effect_facts(n00b_obj_bundle_extract_result_t *facts)
{
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_written(facts) == 0);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_written(facts) == 0);
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_extract_result_temp_root(facts)));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_atomic_used(facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_commit_attempted(facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_commit_completed(facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_rollback_attempted(facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_rollback_succeeded(facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_cleanup_attempted(facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_cleanup_succeeded(facts));
}

static void
assert_no_plan_or_policy_facts(n00b_obj_bundle_extract_result_t *facts)
{
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(facts) == 0);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_planned(facts) == 0);
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_extract_result_policy_kind(facts)));
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_extract_result_policy_scope(facts)));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_fallback_used(facts));
}

static void
assert_policy_facts_with_fallback(
    n00b_obj_bundle_extract_result_t *facts,
    n00b_obj_bundle_policy_kind_t     expected_kind,
    bool                              expected_fallback);
static void
assert_artifact_context(n00b_obj_bundle_error_t *error,
                        n00b_string_t          *path);

static void
assert_policy_facts(n00b_obj_bundle_extract_result_t *facts,
                    n00b_obj_bundle_policy_kind_t     expected_kind)
{
    assert_policy_facts_with_fallback(facts, expected_kind, false);
}

static void
assert_policy_facts_with_fallback(
    n00b_obj_bundle_extract_result_t *facts,
    n00b_obj_bundle_policy_kind_t     expected_kind,
    bool                              expected_fallback)
{
    auto kind = n00b_obj_bundle_extract_result_policy_kind(facts);
    auto scope = n00b_obj_bundle_extract_result_policy_scope(facts);

    N00B_TEST_REQUIRE(n00b_option_is_set(kind));
    N00B_TEST_REQUIRE(n00b_option_get(kind) == expected_kind);
    N00B_TEST_REQUIRE(n00b_option_is_set(scope));
    N00B_TEST_REQUIRE(n00b_option_get(scope)
                      == N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_fallback_used(facts)
                      == expected_fallback);
}

static void
assert_error_policy(n00b_obj_bundle_error_t     *error,
                    n00b_obj_bundle_policy_kind_t expected_kind)
{
    auto kind = n00b_obj_bundle_error_policy_kind(error);
    auto scope = n00b_obj_bundle_error_policy_scope(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(kind));
    N00B_TEST_REQUIRE(n00b_option_get(kind) == expected_kind);
    N00B_TEST_REQUIRE(n00b_option_is_set(scope));
    N00B_TEST_REQUIRE(n00b_option_get(scope)
                      == N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION);
}

static void
assert_pointer_allocator(void *ptr, n00b_allocator_t *expected)
{
    auto owner = n00b_find_allocator(ptr);

    N00B_TEST_REQUIRE(n00b_option_is_set(owner));
    N00B_TEST_REQUIRE(n00b_option_get(owner) == expected);
}

static n00b_string_t *
fixture_dir(n00b_string_t *prefix)
{
    auto dir_r = n00b_new_temp_dir(prefix, r"_dir");

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
    return n00b_buffer_from_bytes(contents->data,
                                  (int64_t)contents->u8_bytes);
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

static bool
symlink_setup_can_be_skipped(int err)
{
    if (err == ENOSYS || err == EPERM || err == EACCES) {
        return true;
    }
#ifdef EOPNOTSUPP
    if (err == EOPNOTSUPP) {
        return true;
    }
#endif
#ifdef ENOTSUP
    if (err == ENOTSUP) {
        return true;
    }
#endif

    return false;
}

static void
assert_default_controls(n00b_obj_bundle_extract_result_t *facts,
                        n00b_string_t                    *root)
{
    assert_string_eq(n00b_obj_bundle_extract_result_destination_root(facts),
                     root);
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_overwrite(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_atomic_requested(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_preserve_modes(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_create_dirs(facts));
    N00B_TEST_REQUIRE(
        !n00b_obj_bundle_extract_result_allow_absolute_paths(facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_allow_parent_refs(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_policy_mode(facts)
                      == N00B_OBJ_BUNDLE_POLICY_ENFORCE);
}

static void
test_invalid_arguments(void)
{
    n00b_string_t *root = r"/tmp/n00b-extract-phase1-no-write";

    n00b_obj_bundle_error_t *error =
        require_extract_error(n00b_obj_bundle_extract(nullptr, root),
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);
    assert_destination(error, root);
    assert_no_extract_facts(error);

    n00b_obj_bundle_t *bundle = new_bundle();

    error = require_extract_error(n00b_obj_bundle_extract(bundle, nullptr),
                                  N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);
    assert_no_destination(error);
    assert_no_extract_facts(error);

    error = require_extract_error(n00b_obj_bundle_extract(bundle, r""),
                                  N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);
    assert_no_destination(error);
    assert_no_extract_facts(error);
}

static void
test_invalid_policy_mode_context(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();
    n00b_string_t     *root  = r"/tmp/n00b-extract-phase1-policy";
    auto result = n00b_obj_bundle_extract(
        bundle,
        root,
        .policy_mode = (n00b_obj_bundle_policy_mode_t)99);

    n00b_obj_bundle_error_t *error =
        require_extract_error(result, N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    assert_destination(error, root);
    assert_extraction_scope(error);

    auto detail = n00b_obj_bundle_error_detail(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(detail));
    N00B_TEST_REQUIRE(n00b_option_get(detail) == 99);

    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_string_eq(n00b_obj_bundle_extract_result_destination_root(facts),
                     root);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_policy_mode(facts)
                      == (n00b_obj_bundle_policy_mode_t)99);
    assert_no_side_effect_facts(facts);
    assert_no_plan_or_policy_facts(facts);
}

static void
test_valid_input_skeleton_default_controls(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();
    n00b_string_t     *root  = n00b_new_temp_path(
        r"n00b_extract_phase1_default_",
        r"_root");
    auto result = n00b_obj_bundle_extract(bundle, root);

    n00b_obj_bundle_extract_result_t *facts = require_extract_ok(result);

    assert_default_controls(facts, root);
    assert_no_side_effect_facts(facts);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(facts) == 0);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_planned(facts) == 0);
    assert_policy_facts(facts, N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
}

static void
test_valid_input_skeleton_custom_controls(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();
    n00b_string_t     *root  = r"/tmp/n00b-extract-phase1-custom";
    auto result = n00b_obj_bundle_extract(
        bundle,
        root,
        .overwrite = true,
        .atomic = false,
        .preserve_modes = false,
        .create_dirs = false,
        .allow_absolute_paths = true,
        .allow_parent_refs = true,
        .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);

    n00b_obj_bundle_extract_result_t *facts = require_extract_ok(result);

    assert_string_eq(n00b_obj_bundle_extract_result_destination_root(facts),
                     root);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_overwrite(facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_atomic_requested(facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_preserve_modes(facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_create_dirs(facts));
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_allow_absolute_paths(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_allow_parent_refs(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_policy_mode(facts)
                      == N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);
    assert_no_side_effect_facts(facts);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(facts) == 0);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_planned(facts) == 0);
    assert_policy_facts(facts, N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
}

static void
test_builtin_default_planning_facts(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_file =
        n00b_obj_bundle_add_artifact(bundle,
                                     r"share/data",
                                     payload_bytes());
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    auto add_exec = n00b_obj_bundle_add_artifact(
        bundle,
        r"bin/tool",
        payload_bytes(),
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
        .mode = 0755);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_exec));

    auto add_dir = n00b_obj_bundle_add_artifact(
        bundle,
        r"empty-dir",
        nullptr,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_dir));

    n00b_string_t *root = r"/tmp/n00b-extract-phase2-builtin";
    auto result = n00b_obj_bundle_extract(
        bundle,
        root,
        .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);
    n00b_obj_bundle_extract_result_t *facts = require_extract_ok(result);

    assert_string_eq(n00b_obj_bundle_extract_result_destination_root(facts),
                     root);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_atomic_requested(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_policy_mode(facts)
                      == N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);
    assert_no_side_effect_facts(facts);
    assert_policy_facts(facts, N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(facts) == 2);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_planned(facts) == 1);
}

static void
test_declarative_policy_selection_facts(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto builtin = n00b_obj_bundle_add_policy(
        bundle,
        1,
        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
    N00B_TEST_REQUIRE(n00b_result_is_ok(builtin));

    n00b_buffer_t *policy_payload =
        make_policy_payload(N00B_OBJ_BUNDLE_POLICY_ID_NONE);
    auto declarative = n00b_obj_bundle_add_policy(
        bundle,
        2,
        N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION,
        .flags = N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
        .priority = 1,
        .payload = policy_payload);
    N00B_TEST_REQUIRE(n00b_result_is_ok(declarative));

    auto add_file =
        n00b_obj_bundle_add_artifact(bundle,
                                     r"payload.bin",
                                     payload_bytes());
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    n00b_string_t *root = r"/tmp/n00b-extract-phase2-declarative";
    auto result = n00b_obj_bundle_extract(
        bundle,
        root,
        .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);
    n00b_obj_bundle_extract_result_t *facts = require_extract_ok(result);

    assert_string_eq(n00b_obj_bundle_extract_result_destination_root(facts),
                     root);
    assert_no_side_effect_facts(facts);
    assert_policy_facts(facts, N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(facts) == 1);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_planned(facts) == 0);
}

static void
test_supported_declarative_fallback_is_not_used(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto builtin = n00b_obj_bundle_add_policy(
        bundle,
        1,
        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
    N00B_TEST_REQUIRE(n00b_result_is_ok(builtin));

    n00b_buffer_t *policy_payload = make_policy_payload(1);
    auto declarative = n00b_obj_bundle_add_policy(
        bundle,
        2,
        N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION,
        .flags = N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
                 | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED,
        .priority = 1,
        .payload = policy_payload,
        .fallback_policy_id = 1);
    N00B_TEST_REQUIRE(n00b_result_is_ok(declarative));

    auto add_file =
        n00b_obj_bundle_add_artifact(bundle,
                                     r"payload.bin",
                                     payload_bytes());
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    n00b_string_t *root = r"/tmp/n00b-extract-phase2-supported-fallback";
    auto result = n00b_obj_bundle_extract(
        bundle,
        root,
        .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);
    n00b_obj_bundle_extract_result_t *facts = require_extract_ok(result);

    assert_string_eq(n00b_obj_bundle_extract_result_destination_root(facts),
                     root);
    assert_no_side_effect_facts(facts);
    assert_policy_facts(facts, N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(facts) == 1);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_planned(facts) == 0);
}

static n00b_obj_bundle_t *
new_fallback_bundle(n00b_allocator_t *allocator)
{
    n00b_obj_bundle_t *bundle = new_bundle_with_allocator(allocator);

    auto builtin = n00b_obj_bundle_add_policy(
        bundle,
        1,
        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
    N00B_TEST_REQUIRE(n00b_result_is_ok(builtin));

    n00b_buffer_t *policy_payload = make_policy_payload(1);
    auto declarative = n00b_obj_bundle_add_policy(
        bundle,
        2,
        N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION,
        .flags = N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
                 | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED,
        .priority = 1,
        .payload = policy_payload,
        .fallback_policy_id = 1);
    N00B_TEST_REQUIRE(n00b_result_is_ok(declarative));

    auto add_file =
        n00b_obj_bundle_add_artifact(bundle,
                                     r"payload.bin",
                                     payload_bytes());
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    return bundle;
}

static void
test_unknown_optional_policy_uses_allowed_fallback(void)
{
    n00b_obj_bundle_t *bundle = new_fallback_bundle(nullptr);
    test_obj_bundle_policy_t *declarative = test_policy_at(bundle, 1);

    declarative->kind = (n00b_obj_bundle_policy_kind_t)99;

    n00b_string_t *root = r"/tmp/n00b-extract-phase2-unknown-fallback";
    auto result = n00b_obj_bundle_extract(
        bundle,
        root,
        .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);
    n00b_obj_bundle_extract_result_t *facts = require_extract_ok(result);

    assert_string_eq(n00b_obj_bundle_extract_result_destination_root(facts),
                     root);
    assert_no_side_effect_facts(facts);
    assert_policy_facts_with_fallback(
        facts,
        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
        true);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(facts) == 1);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_planned(facts) == 0);
}

static void
test_unknown_required_policy_rejects_before_writes(void)
{
    n00b_obj_bundle_t *bundle = new_fallback_bundle(nullptr);
    test_obj_bundle_policy_t *declarative = test_policy_at(bundle, 1);

    declarative->kind  = (n00b_obj_bundle_policy_kind_t)99;
    declarative->flags = N00B_OBJ_BUNDLE_POLICY_F_REQUIRED;

    n00b_string_t *root = r"/tmp/n00b-extract-phase2-unknown-required";
    auto result = n00b_obj_bundle_extract(bundle, root);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result,
                              N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_destination(error, root);
    assert_error_policy(error, (n00b_obj_bundle_policy_kind_t)99);
    assert_no_side_effect_facts(facts);
    assert_no_plan_or_policy_facts(facts);
}

static n00b_obj_bundle_t *
new_embedded_extraction_bundle(n00b_string_t *predicate,
                               uint64_t       flags,
                               bool           add_fallback)
{
    n00b_obj_bundle_t *bundle = new_bundle();
    uint64_t fallback_id = N00B_OBJ_BUNDLE_POLICY_ID_NONE;

    if (add_fallback) {
        fallback_id = 1;
        auto builtin = n00b_obj_bundle_add_policy(
            bundle,
            fallback_id,
            N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
            N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
        N00B_TEST_REQUIRE(n00b_result_is_ok(builtin));
    }

    n00b_buffer_t *payload =
        make_embedded_policy_payload(fallback_id, predicate);
    auto embedded = n00b_obj_bundle_add_policy(
        bundle,
        add_fallback ? 2 : 1,
        N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION,
        .flags = flags,
        .priority = 1,
        .payload = payload,
        .fallback_policy_id = fallback_id);
    N00B_TEST_REQUIRE(n00b_result_is_ok(embedded));

    auto add_file =
        n00b_obj_bundle_add_artifact(bundle,
                                     r"payload.bin",
                                     payload_bytes());
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    return bundle;
}

static void
test_embedded_extraction_validate_only_allows(void)
{
    n00b_obj_bundle_t *bundle = new_embedded_extraction_bundle(
        r"true",
        N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
        false);

    n00b_string_t *root = n00b_new_temp_path(r"n00b_extract_embedded_allow_",
                                             r"_root");
    auto result = n00b_obj_bundle_extract(
        bundle,
        root,
        .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);
    n00b_obj_bundle_extract_result_t *facts = require_extract_ok(result);

    assert_no_side_effect_facts(facts);
    assert_policy_facts(facts, N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(facts) == 1);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_planned(facts) == 0);
    N00B_TEST_REQUIRE(!n00b_path_exists(root));
}

static void
test_embedded_extraction_validate_only_denies(void)
{
    n00b_obj_bundle_t *bundle = new_embedded_extraction_bundle(
        r"false",
        N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
            | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED,
        true);

    n00b_string_t *root = n00b_new_temp_path(r"n00b_extract_embedded_deny_",
                                             r"_root");
    auto result = n00b_obj_bundle_extract(
        bundle,
        root,
        .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result, N00B_OBJ_BUNDLE_ERR_POLICY_DENIED);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_destination(error, root);
    assert_artifact_context(error, r"payload.bin");
    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);
    assert_no_side_effect_facts(facts);
    assert_policy_facts(facts, N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);
    N00B_TEST_REQUIRE(!n00b_path_exists(root));
}

static void
test_embedded_optional_compile_failure_uses_builtin_fallback(void)
{
    n00b_obj_bundle_t *bundle = new_embedded_extraction_bundle(
        r";",
        N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
            | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED,
        true);

    n00b_string_t *root = n00b_new_temp_path(r"n00b_extract_embedded_fallback_",
                                             r"_root");
    auto result = n00b_obj_bundle_extract(
        bundle,
        root,
        .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);
    n00b_obj_bundle_extract_result_t *facts = require_extract_ok(result);

    assert_no_side_effect_facts(facts);
    assert_policy_facts_with_fallback(
        facts,
        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
        true);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(facts) == 1);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_planned(facts) == 0);
    N00B_TEST_REQUIRE(!n00b_path_exists(root));
}

static void
test_embedded_required_compile_failure_rejects_before_writes(void)
{
    n00b_obj_bundle_t *bundle = new_embedded_extraction_bundle(
        r";",
        N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
        false);

    n00b_string_t *root = n00b_new_temp_path(r"n00b_extract_embedded_build_",
                                             r"_root");
    auto result = n00b_obj_bundle_extract(bundle, root);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result, N00B_OBJ_BUNDLE_ERR_BUILD);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_destination(error, root);
    assert_artifact_context(error, r"payload.bin");
    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);
    assert_no_side_effect_facts(facts);
    assert_policy_facts(facts, N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);
    N00B_TEST_REQUIRE(!n00b_path_exists(root));
}

static void
test_embedded_direct_failure_happens_before_writes(void)
{
    n00b_obj_bundle_t *bundle = new_embedded_extraction_bundle(
        r";",
        N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
        false);

    n00b_string_t *root = fixture_dir(r"n00b_extract_embedded_direct_");
    n00b_string_t *payload = fixture_child(root, r"payload.bin");
    auto result = n00b_obj_bundle_extract(bundle, root, .atomic = false);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result, N00B_OBJ_BUNDLE_ERR_BUILD);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_artifact_context(error, r"payload.bin");
    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);
    assert_no_side_effect_facts(facts);
    N00B_TEST_REQUIRE(!n00b_path_exists(payload));

    fixture_rmdir(root);
}

static void
test_embedded_atomic_failure_happens_before_writes(void)
{
    n00b_obj_bundle_t *bundle = new_embedded_extraction_bundle(
        r";",
        N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
        false);

    n00b_string_t *root = n00b_new_temp_path(r"n00b_extract_embedded_atomic_",
                                             r"_root");
    auto result = n00b_obj_bundle_extract(bundle, root);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result, N00B_OBJ_BUNDLE_ERR_BUILD);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_destination(error, root);
    assert_artifact_context(error, r"payload.bin");
    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);
    assert_no_side_effect_facts(facts);
    N00B_TEST_REQUIRE(!n00b_path_exists(root));
}

static void
assert_invalid_fallback_error(n00b_obj_bundle_error_t *error,
                              n00b_string_t          *root)
{
    assert_destination(error, root);
    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1);

    auto detail = n00b_obj_bundle_error_detail(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(detail));
    N00B_TEST_REQUIRE(n00b_option_get(detail) == 1);

    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_no_side_effect_facts(facts);
    assert_no_plan_or_policy_facts(facts);
}

static void
test_disallowed_fallback_rejects_with_extraction_allocator(void)
{
    n00b_arena_t *bundle_arena =
        n00b_new_arena(.size = 32768, .use_gc = true);
    n00b_arena_t *extract_arena =
        n00b_new_arena(.size = 32768, .use_gc = true);
    n00b_obj_bundle_t *bundle =
        new_fallback_bundle((n00b_allocator_t *)bundle_arena);
    test_obj_bundle_policy_t *declarative = test_policy_at(bundle, 1);

    declarative->flags = N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL;

    n00b_string_t *root = r"/tmp/n00b-extract-phase2-disallowed-fallback";
    auto result = n00b_obj_bundle_extract(
        bundle,
        root,
        .allocator = (n00b_allocator_t *)extract_arena);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result, N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    assert_invalid_fallback_error(error, root);
    assert_pointer_allocator(error, (n00b_allocator_t *)extract_arena);
    assert_pointer_allocator(require_extract_facts(error),
                             (n00b_allocator_t *)extract_arena);
}

static void
test_incompatible_fallback_rejects_with_context(void)
{
    n00b_obj_bundle_t *bundle = new_fallback_bundle(nullptr);
    test_obj_bundle_policy_t *builtin = test_policy_at(bundle, 0);

    builtin->priority = 5;

    n00b_string_t *root = r"/tmp/n00b-extract-phase2-incompatible-fallback";
    auto result = n00b_obj_bundle_extract(bundle, root);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result, N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    assert_invalid_fallback_error(error, root);
}

static void
assert_artifact_context(n00b_obj_bundle_error_t *error,
                        n00b_string_t          *path)
{
    auto logical_path = n00b_obj_bundle_error_logical_path(error);
    auto artifact_id = n00b_obj_bundle_error_artifact_id(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(logical_path));
    assert_string_eq(n00b_option_get(logical_path), path);
    N00B_TEST_REQUIRE(n00b_option_is_set(artifact_id));
}

static void
test_unsupported_metadata_and_opaque_reject_before_writes(void)
{
    n00b_obj_bundle_t *metadata_bundle = new_bundle();
    auto add_metadata = n00b_obj_bundle_add_artifact(
        metadata_bundle,
        r"meta/info",
        nullptr,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_METADATA);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_metadata));

    n00b_string_t *metadata_root = r"/tmp/n00b-extract-phase2-metadata";
    auto metadata_result =
        n00b_obj_bundle_extract(metadata_bundle, metadata_root);
    n00b_obj_bundle_error_t *metadata_error =
        require_extract_error(metadata_result,
                              N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE);
    n00b_obj_bundle_extract_result_t *metadata_facts =
        require_extract_facts(metadata_error);

    assert_destination(metadata_error, metadata_root);
    assert_error_policy(metadata_error,
                        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
    assert_artifact_context(metadata_error, r"meta/info");
    assert_no_side_effect_facts(metadata_facts);
    assert_policy_facts(metadata_facts,
                        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(
                          metadata_facts) == 0);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_directories_planned(
                          metadata_facts) == 0);

    n00b_obj_bundle_t *opaque_bundle = new_bundle();
    auto add_opaque = n00b_obj_bundle_add_artifact(
        opaque_bundle,
        r"opaque/blob",
        payload_bytes(),
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_OPAQUE);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_opaque));

    n00b_string_t *opaque_root = r"/tmp/n00b-extract-phase2-opaque";
    auto opaque_result = n00b_obj_bundle_extract(opaque_bundle, opaque_root);
    n00b_obj_bundle_error_t *opaque_error =
        require_extract_error(opaque_result,
                              N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE);
    n00b_obj_bundle_extract_result_t *opaque_facts =
        require_extract_facts(opaque_error);

    assert_destination(opaque_error, opaque_root);
    assert_error_policy(opaque_error,
                        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
    assert_artifact_context(opaque_error, r"opaque/blob");
    assert_no_side_effect_facts(opaque_facts);
    assert_policy_facts(opaque_facts,
                        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
}

static void
test_artifact_flags_reject_before_writes(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();
    auto add_file =
        n00b_obj_bundle_add_artifact(bundle,
                                     r"flagged",
                                     payload_bytes(),
                                     .flags = 1);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    n00b_string_t *root = r"/tmp/n00b-extract-phase2-flags";
    auto result = n00b_obj_bundle_extract(bundle, root);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result,
                              N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_destination(error, root);
    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
    assert_artifact_context(error, r"flagged");
    assert_no_side_effect_facts(facts);
    assert_policy_facts(facts, N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);

    auto detail = n00b_obj_bundle_error_detail(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(detail));
    N00B_TEST_REQUIRE(n00b_option_get(detail) == 1);
}

static void
test_path_collision_rejects_before_writes(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_parent =
        n00b_obj_bundle_add_artifact(bundle, r"bin", payload_bytes());
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_parent));

    auto add_child =
        n00b_obj_bundle_add_artifact(bundle, r"bin/tool", payload_bytes());
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_child));

    n00b_string_t *root = r"/tmp/n00b-extract-phase2-collision";
    auto result = n00b_obj_bundle_extract(bundle, root);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result,
                              N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_destination(error, root);
    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
    assert_artifact_context(error, r"bin");
    assert_no_side_effect_facts(facts);
    assert_policy_facts(facts, N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
}

static void
test_create_dirs_denial_rejects_before_writes(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_file =
        n00b_obj_bundle_add_artifact(bundle,
                                     r"nested/payload.bin",
                                     payload_bytes());
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    n00b_string_t *root = r"/tmp/n00b-extract-phase2-create-dirs";
    auto result = n00b_obj_bundle_extract(bundle, root, .create_dirs = false);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result,
                              N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_destination(error, root);
    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
    assert_artifact_context(error, r"nested/payload.bin");
    assert_no_side_effect_facts(facts);
    assert_policy_facts(facts, N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_create_dirs(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(facts) == 0);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_planned(facts) == 0);
}

static void
test_direct_and_atomic_modes_share_planner(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_file =
        n00b_obj_bundle_add_artifact(bundle, r"payload.bin", payload_bytes());
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    auto add_dir = n00b_obj_bundle_add_artifact(
        bundle,
        r"empty",
        nullptr,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_dir));

    n00b_string_t *atomic_root = r"/tmp/n00b-extract-phase2-atomic";
    auto atomic_result = n00b_obj_bundle_extract(
        bundle,
        atomic_root,
        .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);
    n00b_obj_bundle_extract_result_t *atomic_facts =
        require_extract_ok(atomic_result);

    n00b_string_t *direct_root = r"/tmp/n00b-extract-phase2-direct";
    auto direct_result = n00b_obj_bundle_extract(
        bundle,
        direct_root,
        .atomic = false,
        .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);
    n00b_obj_bundle_extract_result_t *direct_facts =
        require_extract_ok(direct_result);

    assert_no_side_effect_facts(atomic_facts);
    assert_no_side_effect_facts(direct_facts);
    assert_policy_facts(atomic_facts,
                        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
    assert_policy_facts(direct_facts,
                        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_atomic_requested(
                          atomic_facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_atomic_requested(
        direct_facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(
                          atomic_facts) == 1);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(
                          direct_facts) == 1);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_directories_planned(
                          atomic_facts) == 1);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_directories_planned(
                          direct_facts) == 1);
}

static void
test_direct_extraction_materializes_supported_artifacts(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_var = n00b_obj_bundle_add_artifact(
        bundle,
        r"var",
        nullptr,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_var));

    auto add_empty_dir = n00b_obj_bundle_add_artifact(
        bundle,
        r"var/empty",
        nullptr,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY,
        .mode = 0700);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_empty_dir));

    auto add_file = n00b_obj_bundle_add_artifact(
        bundle,
        r"share/data.txt",
        fixture_buffer(r"regular payload"));
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    auto add_exec = n00b_obj_bundle_add_artifact(
        bundle,
        r"bin/tool",
        fixture_buffer(r"#!/bin/tool\n"),
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
        .mode = 0755);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_exec));

    auto add_empty_file = n00b_obj_bundle_add_artifact(
        bundle,
        r"empty-file",
        fixture_buffer(r""));
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_empty_file));

    n00b_string_t *root = n00b_new_temp_path(r"n00b_extract_direct_",
                                             r"_root");
    auto result = n00b_obj_bundle_extract(bundle, root, .atomic = false);
    n00b_obj_bundle_extract_result_t *facts = require_extract_ok(result);

    assert_string_eq(n00b_obj_bundle_extract_result_destination_root(facts),
                     root);
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_atomic_requested(facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_atomic_used(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(facts) == 3);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_planned(facts) == 2);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_written(facts) == 3);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_written(facts) == 5);
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_commit_attempted(facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_rollback_attempted(facts));
    assert_policy_facts(facts, N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);

    n00b_string_t *var = fixture_child(root, r"var");
    n00b_string_t *empty_dir = fixture_child(var, r"empty");
    n00b_string_t *share = fixture_child(root, r"share");
    n00b_string_t *data = fixture_child(share, r"data.txt");
    n00b_string_t *bin = fixture_child(root, r"bin");
    n00b_string_t *tool = fixture_child(bin, r"tool");
    n00b_string_t *empty_file = fixture_child(root, r"empty-file");

    N00B_TEST_REQUIRE(n00b_path_is_directory(var));
    N00B_TEST_REQUIRE(n00b_path_is_directory(empty_dir));
    fixture_assert_bytes(data, r"regular payload");
    fixture_assert_bytes(tool, r"#!/bin/tool\n");
    fixture_assert_bytes(empty_file, r"");

    auto mode_r = n00b_path_get_mode(tool);
    if (n00b_result_is_ok(mode_r)) {
        N00B_TEST_REQUIRE((n00b_result_get(mode_r) & 0111u) != 0);
    }
    else {
        N00B_TEST_REQUIRE(n00b_result_get_err(mode_r) == ENOSYS);
    }

    fixture_unlink(data);
    fixture_unlink(tool);
    fixture_unlink(empty_file);
    fixture_rmdir(empty_dir);
    fixture_rmdir(var);
    fixture_rmdir(share);
    fixture_rmdir(bin);
    fixture_rmdir(root);
}

static void
test_direct_failure_preserves_created_directory_facts(void)
{
    n00b_arena_t *extract_arena =
        n00b_new_arena(.size = 32768, .use_gc = true);
    n00b_allocator_t *allocator = (n00b_allocator_t *)extract_arena;
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_file = n00b_obj_bundle_add_artifact(
        bundle,
        r"nested/payload.bin",
        fixture_buffer(r"payload"),
        .mode = 010000u);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    n00b_string_t *root = n00b_new_temp_path(
        r"n00b_extract_failure_dirs_",
        r"_root");
    n00b_string_t *nested = fixture_child(root, r"nested");
    n00b_string_t *payload = fixture_child(nested, r"payload.bin");
    auto result = n00b_obj_bundle_extract(bundle,
                                          root,
                                          .atomic = false,
                                          .allocator = allocator);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_artifact_context(error, r"nested/payload.bin");
    assert_destination(error, payload);
    assert_pointer_allocator(error, allocator);
    assert_pointer_allocator(facts, allocator);

    auto destination = n00b_obj_bundle_error_destination_path(error);
    N00B_TEST_REQUIRE(n00b_option_is_set(destination));
    assert_pointer_allocator(n00b_option_get(destination), allocator);

    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_written(facts) == 0);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_written(facts) == 2);
    N00B_TEST_REQUIRE(n00b_path_is_directory(root));
    N00B_TEST_REQUIRE(n00b_path_is_directory(nested));
    N00B_TEST_REQUIRE(!n00b_path_exists(payload));

    fixture_rmdir(nested);
    fixture_rmdir(root);
}

static void
test_validate_only_returns_success_without_writes(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_file = n00b_obj_bundle_add_artifact(
        bundle,
        r"nested/payload.bin",
        fixture_buffer(r"payload"));
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    n00b_string_t *root = n00b_new_temp_path(r"n00b_extract_validate_",
                                             r"_root");
    auto result = n00b_obj_bundle_extract(
        bundle,
        root,
        .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);
    n00b_obj_bundle_extract_result_t *facts = require_extract_ok(result);

    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(facts) == 1);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_planned(facts) == 0);
    assert_no_side_effect_facts(facts);
    N00B_TEST_REQUIRE(!n00b_path_exists(root));
}

static void
test_atomic_extraction_materializes_supported_artifacts(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_var = n00b_obj_bundle_add_artifact(
        bundle,
        r"var",
        nullptr,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_var));

    auto add_empty_dir = n00b_obj_bundle_add_artifact(
        bundle,
        r"var/empty",
        nullptr,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY,
        .mode = 0700);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_empty_dir));

    auto add_file = n00b_obj_bundle_add_artifact(
        bundle,
        r"share/data.txt",
        fixture_buffer(r"regular payload"));
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    auto add_exec = n00b_obj_bundle_add_artifact(
        bundle,
        r"bin/tool",
        fixture_buffer(r"#!/bin/tool\n"),
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
        .mode = 0755);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_exec));

    auto add_empty_file = n00b_obj_bundle_add_artifact(
        bundle,
        r"empty-file",
        fixture_buffer(r""));
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_empty_file));

    n00b_string_t *root = n00b_new_temp_path(r"n00b_extract_atomic_",
                                             r"_root");
    auto result = n00b_obj_bundle_extract(bundle, root);
    n00b_obj_bundle_extract_result_t *facts = require_extract_ok(result);

    assert_string_eq(n00b_obj_bundle_extract_result_destination_root(facts),
                     root);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_atomic_requested(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_atomic_used(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(facts) == 3);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_planned(facts) == 2);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_written(facts) == 3);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_written(facts) == 5);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_commit_attempted(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_commit_completed(facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_rollback_attempted(facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_cleanup_attempted(facts));
    assert_policy_facts(facts, N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);

    auto temp_root = n00b_obj_bundle_extract_result_temp_root(facts);
    N00B_TEST_REQUIRE(n00b_option_is_set(temp_root));
    N00B_TEST_REQUIRE(!n00b_path_exists(n00b_option_get(temp_root)));

    n00b_string_t *var = fixture_child(root, r"var");
    n00b_string_t *empty_dir = fixture_child(var, r"empty");
    n00b_string_t *share = fixture_child(root, r"share");
    n00b_string_t *data = fixture_child(share, r"data.txt");
    n00b_string_t *bin = fixture_child(root, r"bin");
    n00b_string_t *tool = fixture_child(bin, r"tool");
    n00b_string_t *empty_file = fixture_child(root, r"empty-file");

    N00B_TEST_REQUIRE(n00b_path_is_directory(var));
    N00B_TEST_REQUIRE(n00b_path_is_directory(empty_dir));
    fixture_assert_bytes(data, r"regular payload");
    fixture_assert_bytes(tool, r"#!/bin/tool\n");
    fixture_assert_bytes(empty_file, r"");

    auto mode_r = n00b_path_get_mode(tool);
    if (n00b_result_is_ok(mode_r)) {
        N00B_TEST_REQUIRE((n00b_result_get(mode_r) & 0111u) != 0);
    }
    else {
        N00B_TEST_REQUIRE(n00b_result_get_err(mode_r) == ENOSYS);
    }

    auto cleanup_r = n00b_path_remove_tree(root, .ignore_missing = true);
    N00B_TEST_REQUIRE(n00b_result_is_ok(cleanup_r));
}

static void
test_atomic_existing_root_rejects_without_writes(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_existing = n00b_obj_bundle_add_artifact(
        bundle,
        r"keep.txt",
        fixture_buffer(r"new"));
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_existing));

    n00b_string_t *root = fixture_dir(r"n00b_extract_atomic_existing_");
    n00b_string_t *keep = fixture_child(root, r"keep.txt");
    fixture_write(keep, r"old");

    auto result = n00b_obj_bundle_extract(bundle, root, .overwrite = true);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result, N00B_OBJ_BUNDLE_ERR_BUILD);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_destination(error, root);
    assert_no_side_effect_facts(facts);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_overwrite(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_planned(facts) == 1);
    fixture_assert_bytes(keep, r"old");

    fixture_unlink(keep);
    fixture_rmdir(root);
}

static void
test_atomic_staging_failure_cleans_temp_tree(void)
{
    n00b_arena_t *extract_arena =
        n00b_new_arena(.size = 32768, .use_gc = true);
    n00b_allocator_t *allocator = (n00b_allocator_t *)extract_arena;
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_file = n00b_obj_bundle_add_artifact(
        bundle,
        r"nested/payload.bin",
        fixture_buffer(r"payload"),
        .mode = 010000u);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    n00b_string_t *root = n00b_new_temp_path(
        r"n00b_extract_atomic_failure_",
        r"_root");
    auto result = n00b_obj_bundle_extract(bundle,
                                          root,
                                          .allocator = allocator);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result,
                              N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_artifact_context(error, r"nested/payload.bin");
    assert_pointer_allocator(error, allocator);
    assert_pointer_allocator(facts, allocator);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_atomic_used(facts));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_extract_result_commit_attempted(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_cleanup_attempted(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_cleanup_succeeded(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_written(facts) == 0);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_extract_result_directories_written(facts) == 2);
    N00B_TEST_REQUIRE(!n00b_path_exists(root));

    auto temp_root = n00b_obj_bundle_extract_result_temp_root(facts);
    N00B_TEST_REQUIRE(n00b_option_is_set(temp_root));
    N00B_TEST_REQUIRE(!n00b_path_exists(n00b_option_get(temp_root)));
}

static void
test_direct_overwrite_rejection_preserves_existing_files(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_existing = n00b_obj_bundle_add_artifact(
        bundle,
        r"keep.txt",
        fixture_buffer(r"new"));
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_existing));

    auto add_other = n00b_obj_bundle_add_artifact(
        bundle,
        r"other.txt",
        fixture_buffer(r"other"));
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_other));

    n00b_string_t *root = fixture_dir(r"n00b_extract_overwrite_reject_");
    n00b_string_t *keep = fixture_child(root, r"keep.txt");
    n00b_string_t *other = fixture_child(root, r"other.txt");
    fixture_write(keep, r"old");

    auto result = n00b_obj_bundle_extract(bundle, root, .atomic = false);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result, N00B_OBJ_BUNDLE_ERR_BUILD);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_destination(error, keep);
    assert_artifact_context(error, r"keep.txt");
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_written(facts) == 0);
    fixture_assert_bytes(keep, r"old");
    N00B_TEST_REQUIRE(!n00b_path_exists(other));

    fixture_unlink(keep);
    fixture_rmdir(root);
}

static void
test_direct_overwrite_success_replaces_file(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_file = n00b_obj_bundle_add_artifact(
        bundle,
        r"replace.txt",
        fixture_buffer(r"new contents"));
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    n00b_string_t *root = fixture_dir(r"n00b_extract_overwrite_success_");
    n00b_string_t *path = fixture_child(root, r"replace.txt");
    fixture_write(path, r"old contents");

    auto result = n00b_obj_bundle_extract(bundle,
                                          root,
                                          .atomic = false,
                                          .overwrite = true);
    n00b_obj_bundle_extract_result_t *facts = require_extract_ok(result);

    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_overwrite(facts));
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_files_written(facts) == 1);
    fixture_assert_bytes(path, r"new contents");

    fixture_unlink(path);
    fixture_rmdir(root);
}

static void
test_direct_extraction_rejects_symlinked_parent_before_writes(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_file = n00b_obj_bundle_add_artifact(
        bundle,
        r"linked-dir/payload.txt",
        fixture_buffer(r"new"));
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    n00b_string_t *root = fixture_dir(r"n00b_extract_symlink_parent_");
    n00b_string_t *outside = fixture_dir(
        r"n00b_extract_symlink_parent_outside_");
    n00b_string_t *outside_file = fixture_child(outside, r"sentinel.txt");
    n00b_string_t *link_path = fixture_child(root, r"linked-dir");
    n00b_string_t *payload_path = fixture_child(link_path, r"payload.txt");

    fixture_write(outside_file, r"outside");

    if (symlink(outside->data, link_path->data) != 0) {
        int err = errno;

        fixture_unlink(outside_file);
        fixture_rmdir(outside);
        fixture_rmdir(root);
        N00B_TEST_REQUIRE(symlink_setup_can_be_skipped(err));
        return;
    }

    auto result = n00b_obj_bundle_extract(bundle, root, .atomic = false);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result, N00B_OBJ_BUNDLE_ERR_BUILD);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_destination(error, link_path);
    assert_artifact_context(error, r"linked-dir/payload.txt");
    assert_no_side_effect_facts(facts);
    fixture_assert_bytes(outside_file, r"outside");
    N00B_TEST_REQUIRE(!n00b_path_exists(payload_path));

    fixture_unlink(link_path);
    fixture_unlink(outside_file);
    fixture_rmdir(outside);
    fixture_rmdir(root);
}

static void
test_direct_overwrite_rejects_symlinked_file_destination(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_file = n00b_obj_bundle_add_artifact(
        bundle,
        r"payload.txt",
        fixture_buffer(r"new"));
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    n00b_string_t *root = fixture_dir(r"n00b_extract_symlink_file_");
    n00b_string_t *outside = fixture_dir(
        r"n00b_extract_symlink_file_outside_");
    n00b_string_t *outside_file = fixture_child(outside, r"sentinel.txt");
    n00b_string_t *link_path = fixture_child(root, r"payload.txt");

    fixture_write(outside_file, r"outside");

    if (symlink(outside_file->data, link_path->data) != 0) {
        int err = errno;

        fixture_unlink(outside_file);
        fixture_rmdir(outside);
        fixture_rmdir(root);
        N00B_TEST_REQUIRE(symlink_setup_can_be_skipped(err));
        return;
    }

    auto result = n00b_obj_bundle_extract(bundle,
                                          root,
                                          .atomic = false,
                                          .overwrite = true);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result, N00B_OBJ_BUNDLE_ERR_BUILD);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_destination(error, link_path);
    assert_artifact_context(error, r"payload.txt");
    assert_no_side_effect_facts(facts);
    N00B_TEST_REQUIRE(n00b_obj_bundle_extract_result_overwrite(facts));
    fixture_assert_bytes(outside_file, r"outside");

    fixture_unlink(link_path);
    fixture_unlink(outside_file);
    fixture_rmdir(outside);
    fixture_rmdir(root);
}

static void
test_direct_planner_rejection_happens_before_writes(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_file =
        n00b_obj_bundle_add_artifact(bundle,
                                     r"ok.txt",
                                     fixture_buffer(r"ok"));
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    auto add_metadata = n00b_obj_bundle_add_artifact(
        bundle,
        r"meta/info",
        nullptr,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_METADATA);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_metadata));

    n00b_string_t *root = fixture_dir(r"n00b_extract_plan_reject_");
    n00b_string_t *ok_path = fixture_child(root, r"ok.txt");

    auto result = n00b_obj_bundle_extract(bundle, root, .atomic = false);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result,
                              N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_no_side_effect_facts(facts);
    assert_artifact_context(error, r"meta/info");
    N00B_TEST_REQUIRE(!n00b_path_exists(ok_path));

    fixture_rmdir(root);
}

static void
test_atomic_planner_rejection_happens_before_writes(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_file =
        n00b_obj_bundle_add_artifact(bundle,
                                     r"ok.txt",
                                     fixture_buffer(r"ok"));
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    auto add_metadata = n00b_obj_bundle_add_artifact(
        bundle,
        r"meta/info",
        nullptr,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_METADATA);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_metadata));

    n00b_string_t *root = n00b_new_temp_path(
        r"n00b_extract_atomic_plan_reject_",
        r"_root");
    n00b_string_t *ok_path = fixture_child(root, r"ok.txt");

    auto result = n00b_obj_bundle_extract(bundle, root);
    n00b_obj_bundle_error_t *error =
        require_extract_error(result,
                              N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE);
    n00b_obj_bundle_extract_result_t *facts = require_extract_facts(error);

    assert_no_side_effect_facts(facts);
    assert_artifact_context(error, r"meta/info");
    N00B_TEST_REQUIRE(!n00b_path_exists(root));
    N00B_TEST_REQUIRE(!n00b_path_exists(ok_path));
}

static void
test_error_strings(void)
{
    N00B_TEST_REQUIRE(n00b_obj_bundle_err_str(
                          N00B_OBJ_BUNDLE_ERR_EXTRACT_UNSUPPORTED)
                      != nullptr);
    N00B_TEST_REQUIRE(n00b_obj_bundle_err_str(-3999) != nullptr);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_embedded_extraction_validate_only_allows();
    test_embedded_extraction_validate_only_denies();
    test_embedded_optional_compile_failure_uses_builtin_fallback();
    test_embedded_required_compile_failure_rejects_before_writes();
    test_embedded_direct_failure_happens_before_writes();
    test_embedded_atomic_failure_happens_before_writes();

    test_invalid_arguments();
    test_invalid_policy_mode_context();
    test_valid_input_skeleton_default_controls();
    test_valid_input_skeleton_custom_controls();
    test_builtin_default_planning_facts();
    test_declarative_policy_selection_facts();
    test_supported_declarative_fallback_is_not_used();
    test_unknown_optional_policy_uses_allowed_fallback();
    test_unknown_required_policy_rejects_before_writes();
    test_disallowed_fallback_rejects_with_extraction_allocator();
    test_incompatible_fallback_rejects_with_context();
    test_unsupported_metadata_and_opaque_reject_before_writes();
    test_artifact_flags_reject_before_writes();
    test_path_collision_rejects_before_writes();
    test_create_dirs_denial_rejects_before_writes();
    test_direct_and_atomic_modes_share_planner();
    test_direct_extraction_materializes_supported_artifacts();
    test_direct_failure_preserves_created_directory_facts();
    test_validate_only_returns_success_without_writes();
    test_atomic_extraction_materializes_supported_artifacts();
    test_atomic_existing_root_rejects_without_writes();
    test_atomic_staging_failure_cleans_temp_tree();
    test_direct_overwrite_rejection_preserves_existing_files();
    test_direct_overwrite_success_replaces_file();
    test_direct_extraction_rejects_symlinked_parent_before_writes();
    test_direct_overwrite_rejects_symlinked_file_destination();
    test_direct_planner_rejection_happens_before_writes();
    test_atomic_planner_rejection_happens_before_writes();
    test_error_strings();

    return 0;
}
