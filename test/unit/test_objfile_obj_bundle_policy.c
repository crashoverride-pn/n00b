#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "compiler/objfile/obj_bundle.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "internal/compiler/objfile/obj_bundle_policy.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"
#include <string.h>

#define N00B_TEST_REQUIRE(expr) n00b_require((expr), #expr)

#define TEST_EMBEDDED_POLICY_COMPAT_FLAGS_OFF 16u
#define TEST_EMBEDDED_POLICY_FALLBACK_ID_OFF  24u
#define TEST_EMBEDDED_POLICY_SOURCE_LEN_OFF   32u

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
make_embedded_policy_payload(uint64_t fallback_policy_id,
                             n00b_string_t *source)
{
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
    write_le64(data, TEST_EMBEDDED_POLICY_SOURCE_LEN_OFF, source->u8_bytes);
    memcpy(data + N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF,
           source->data,
           source->u8_bytes);

    return payload;
}

static n00b_eval_session_t *
require_policy_session(n00b_obj_bundle_policy_scope_t scope)
{
    auto result = n00b_obj_bundle_policy_eval_session_new(scope);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    return n00b_result_get(result);
}

static n00b_obj_bundle_error_t *
require_policy_error(n00b_result_t(bool) result,
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

static void
assert_error_policy(n00b_obj_bundle_error_t        *error,
                    n00b_obj_bundle_policy_scope_t  expected_scope)
{
    auto kind = n00b_obj_bundle_error_policy_kind(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(kind));
    N00B_TEST_REQUIRE(n00b_option_get(kind)
                      == N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);

    auto scope = n00b_obj_bundle_error_policy_scope(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(scope));
    N00B_TEST_REQUIRE(n00b_option_get(scope) == expected_scope);
}

static void
assert_error_path(n00b_obj_bundle_error_t *error, n00b_string_t *path)
{
    auto got = n00b_obj_bundle_error_logical_path(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(got));
    N00B_TEST_REQUIRE(n00b_unicode_str_eq(n00b_option_get(got), path));
}

static void
assert_detail_is_set(n00b_obj_bundle_error_t *error)
{
    auto detail = n00b_obj_bundle_error_detail(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(detail));
}

static void
require_policy_allow(n00b_eval_session_t              *session,
                     n00b_string_t                    *predicate,
                     n00b_obj_bundle_policy_scope_t    scope,
                     n00b_obj_bundle_policy_context_t *context)
{
    n00b_buffer_t *payload = make_embedded_policy_payload(
        N00B_OBJ_BUNDLE_POLICY_ID_NONE,
        predicate);
    auto result = n00b_obj_bundle_policy_evaluate_embedded(
        session,
        payload,
        N00B_OBJ_BUNDLE_POLICY_ID_NONE,
        scope,
        context);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    N00B_TEST_REQUIRE(n00b_result_get(result));
}

static void
test_true_predicate_allows(n00b_eval_session_t *session)
{
    n00b_obj_bundle_policy_context_t *context =
        n00b_obj_bundle_policy_context_for_extraction(
            r"bin/tool",
            N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE);

    require_policy_allow(session,
                         r"true",
                         N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION,
                         context);
}

static void
test_false_predicate_denies_with_context(n00b_eval_session_t *session)
{
    n00b_obj_bundle_policy_context_t *context =
        n00b_obj_bundle_policy_context_for_extraction(
            r"bin/tool",
            N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE);
    n00b_buffer_t *payload = make_embedded_policy_payload(
        N00B_OBJ_BUNDLE_POLICY_ID_NONE,
        r"false");

    auto result = n00b_obj_bundle_policy_evaluate_embedded(
        session,
        payload,
        N00B_OBJ_BUNDLE_POLICY_ID_NONE,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION,
        context);
    n00b_obj_bundle_error_t *error =
        require_policy_error(result, N00B_OBJ_BUNDLE_ERR_POLICY_DENIED);

    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION);
    assert_error_path(error, r"bin/tool");
    assert_detail_is_set(error);
}

static void
test_extraction_context_accessors(n00b_eval_session_t *session)
{
    n00b_obj_bundle_policy_context_t *context =
        n00b_obj_bundle_policy_context_for_extraction(
            r"bin/tool",
            N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
            .overwrite = true,
            .create_dirs = false,
            .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);

    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_scope(context)
        == N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION);
    N00B_TEST_REQUIRE(n00b_unicode_str_eq(
        n00b_obj_bundle_policy_context_logical_path(context),
        r"bin/tool"));
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_artifact_kind(context)
        == N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_selection_source(context)
        == N00B_OBJ_BUNDLE_EXEC_SELECTION_NONE);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_overwrite(context) == true);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_create_dirs(context) == false);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_inherit_env(context) == false);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_strict_selector(context) == false);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_requested_mode(context)
        == N00B_OBJ_BUNDLE_EXEC_AUTO);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_policy_mode(context)
        == N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);

    require_policy_allow(session,
                         r"arg.logical_path == \"bin/tool\"",
                         N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION,
                         context);
    require_policy_allow(session,
                         r"arg.overwrite == true",
                         N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION,
                         context);
}

static void
test_execution_context_accessors(n00b_eval_session_t *session)
{
    n00b_obj_bundle_policy_context_t *context =
        n00b_obj_bundle_policy_context_for_execution(
            r"bin/tool",
            N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
            .selection_source = N00B_OBJ_BUNDLE_EXEC_SELECTION_SELECTOR_MAPPING,
            .inherit_env = false,
            .strict_selector = true,
            .requested_mode = N00B_OBJ_BUNDLE_EXEC_EXTRACTED,
            .policy_mode = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);

    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_scope(context)
        == N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION);
    N00B_TEST_REQUIRE(n00b_unicode_str_eq(
        n00b_obj_bundle_policy_context_logical_path(context),
        r"bin/tool"));
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_artifact_kind(context)
        == N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_selection_source(context)
        == N00B_OBJ_BUNDLE_EXEC_SELECTION_SELECTOR_MAPPING);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_overwrite(context) == false);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_create_dirs(context) == false);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_inherit_env(context) == false);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_strict_selector(context) == true);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_requested_mode(context)
        == N00B_OBJ_BUNDLE_EXEC_EXTRACTED);
    N00B_TEST_REQUIRE(
        n00b_obj_bundle_policy_context_policy_mode(context)
        == N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);

    require_policy_allow(session,
                         r"arg.selection_source == 2",
                         N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
                         context);
}

static void
test_null_session_predicate_uses_owned_eval_session(void)
{
    n00b_obj_bundle_policy_context_t *context =
        n00b_obj_bundle_policy_context_for_execution(
            r"bin/tool",
            N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
            .selection_source =
                N00B_OBJ_BUNDLE_EXEC_SELECTION_SELECTOR_MAPPING);

    require_policy_allow(nullptr,
                         r"arg.selection_source == 2",
                         N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
                         context);
}

static void
test_compile_failure_is_structured(n00b_eval_session_t *session)
{
    n00b_obj_bundle_policy_context_t *context =
        n00b_obj_bundle_policy_context_for_execution(
            r"bin/tool",
            N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE);
    n00b_buffer_t *payload = make_embedded_policy_payload(
        N00B_OBJ_BUNDLE_POLICY_ID_NONE,
        r".");

    auto result = n00b_obj_bundle_policy_evaluate_embedded(
        session,
        payload,
        N00B_OBJ_BUNDLE_POLICY_ID_NONE,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
        context);
    n00b_obj_bundle_error_t *error =
        require_policy_error(result, N00B_OBJ_BUNDLE_ERR_BUILD);

    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION);
    assert_error_path(error, r"bin/tool");
    assert_detail_is_set(error);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    n00b_eval_session_t *session =
        require_policy_session(N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION);

    test_true_predicate_allows(session);
    test_false_predicate_denies_with_context(session);
    test_extraction_context_accessors(session);
    test_execution_context_accessors(session);
    test_null_session_predicate_uses_owned_eval_session();
    test_compile_failure_is_structured(session);

    return 0;
}
