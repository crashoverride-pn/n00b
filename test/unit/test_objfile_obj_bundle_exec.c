#include "n00b.h"
#include "adt/dict.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "compiler/objfile/obj_bundle.h"
#include "core/arena.h"
#include "core/buffer.h"
#include "core/env.h"
#include "core/memory_info.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#include <string.h>

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
#define TEST_DECL_EXEC_DEFAULT_EXEC           0x01ull
#define TEST_DECL_EXEC_SELECTOR_MAPPING       0x02ull
#define TEST_DECL_EXEC_DEFAULT                0x03ull
#define TEST_N00B_EVAL_ERR_PARSE             -6
#define TEST_EMBEDDED_POLICY_RESERVED0_OFF    12u
#define TEST_EMBEDDED_POLICY_COMPAT_FLAGS_OFF 16u
#define TEST_EMBEDDED_POLICY_FALLBACK_ID_OFF  24u
#define TEST_EMBEDDED_POLICY_SOURCE_LEN_OFF   32u
#define TEST_EMBEDDED_POLICY_RESERVED1_OFF    40u

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

static n00b_buffer_t *
payload_bytes(void)
{
    return n00b_buffer_from_cstr("payload");
}

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

static void
require_bool_ok(n00b_result_t(bool) result)
{
    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    N00B_TEST_REQUIRE(n00b_result_get(result));
}

static test_obj_bundle_shadow_t *
shadow_bundle(n00b_obj_bundle_t *bundle)
{
    return (test_obj_bundle_shadow_t *)bundle;
}

static test_obj_bundle_policy_t *
test_policy_at(n00b_obj_bundle_t *bundle, size_t index)
{
    test_obj_bundle_shadow_t *shadow = shadow_bundle(bundle);

    N00B_TEST_REQUIRE(index < shadow->policies.len);
    return shadow->policies.data[index];
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
make_policy_payload(uint64_t fallback_policy_id, uint64_t exec_flags)
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
    write_le64(bytes, TEST_DECL_POLICY_EXEC_FLAGS_OFF, exec_flags);
    write_le64(bytes, TEST_DECL_POLICY_FALLBACK_ID_OFF,
               fallback_policy_id);
    write_le64(bytes, TEST_DECL_POLICY_RESERVED1_OFF, 0);

    n00b_buffer_t *payload = n00b_buffer_new(TEST_DECL_POLICY_SIZE);

    memcpy(payload->data, bytes, TEST_DECL_POLICY_SIZE);
    return payload;
}

static n00b_buffer_t *
make_embedded_policy_payload(uint64_t       fallback_policy_id,
                             n00b_buffer_t *source)
{
    size_t len = N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF
                 + source->byte_len;
    n00b_buffer_t *payload = n00b_buffer_new((int64_t)len);
    uint8_t       *data    = (uint8_t *)payload->data;

    memcpy(data,
           N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC,
           N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC_LEN);
    write_le16(data, 8, N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAJOR);
    write_le16(data, 10, N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MINOR);
    write_le32(data, TEST_EMBEDDED_POLICY_RESERVED0_OFF, 0);
    write_le64(data,
               TEST_EMBEDDED_POLICY_COMPAT_FLAGS_OFF,
               N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SUPPORTED_COMPAT_FLAGS);
    write_le64(data, TEST_EMBEDDED_POLICY_FALLBACK_ID_OFF, fallback_policy_id);
    write_le64(data,
               TEST_EMBEDDED_POLICY_SOURCE_LEN_OFF,
               (uint64_t)source->byte_len);
    write_le64(data, TEST_EMBEDDED_POLICY_RESERVED1_OFF, 0);
    memcpy(data + N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF,
           source->data,
           source->byte_len);

    return payload;
}

static void
add_executable(n00b_obj_bundle_t *bundle, n00b_string_t *logical_path)
{
    require_bool_ok(n00b_obj_bundle_add_artifact(
        bundle,
        logical_path,
        payload_bytes(),
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE));
}

static n00b_obj_bundle_t *
new_default_exec_bundle(void)
{
    n00b_obj_bundle_t *bundle = new_bundle_with_allocator(nullptr);
    n00b_string_t     *path   = r"bin/default";

    add_executable(bundle, path);
    require_bool_ok(n00b_obj_bundle_set_default_exec(bundle, path));

    return bundle;
}

static n00b_obj_bundle_t *
new_default_exec_bundle_with_allocator(n00b_allocator_t *allocator)
{
    n00b_obj_bundle_t *bundle = new_bundle_with_allocator(allocator);
    n00b_string_t     *path   = r"bin/default";

    add_executable(bundle, path);
    require_bool_ok(n00b_obj_bundle_set_default_exec(bundle, path));

    return bundle;
}

static n00b_obj_bundle_t *
new_selector_bundle(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();
    n00b_string_t     *selector = r"tool";
    n00b_string_t     *path     = r"bin/tool";

    add_executable(bundle, path);
    require_bool_ok(n00b_obj_bundle_add_exec_mapping(bundle, selector, path));

    return bundle;
}

static void
add_builtin_policy(n00b_obj_bundle_t           *bundle,
                   uint64_t                    policy_id,
                   n00b_obj_bundle_policy_scope_t scope)
{
    auto result = n00b_obj_bundle_add_policy(
        bundle,
        policy_id,
        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
        scope);

    require_bool_ok(result);
}

static void
add_declarative_policy(n00b_obj_bundle_t           *bundle,
                       uint64_t                    policy_id,
                       n00b_obj_bundle_policy_scope_t scope,
                       uint64_t                    exec_flags,
                       uint64_t                    flags,
                       uint64_t                    priority,
                       uint64_t                    fallback_policy_id)
{
    n00b_buffer_t *payload =
        make_policy_payload(fallback_policy_id, exec_flags);

    auto result = n00b_obj_bundle_add_policy(
        bundle,
        policy_id,
        N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1,
        scope,
        .flags = flags,
        .priority = priority,
        .payload = payload,
        .fallback_policy_id = fallback_policy_id);

    require_bool_ok(result);
}

static void
add_embedded_policy(n00b_obj_bundle_t           *bundle,
                    uint64_t                    policy_id,
                    n00b_obj_bundle_policy_scope_t scope,
                    uint64_t                    flags,
                    uint64_t                    priority,
                    uint64_t                    fallback_policy_id,
                    n00b_buffer_t              *source)
{
    n00b_buffer_t *payload =
        make_embedded_policy_payload(fallback_policy_id, source);

    auto result = n00b_obj_bundle_add_policy(
        bundle,
        policy_id,
        N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B,
        scope,
        .flags = flags,
        .priority = priority,
        .payload = payload,
        .fallback_policy_id = fallback_policy_id);

    require_bool_ok(result);
}

static n00b_obj_bundle_t *
new_exec_fallback_bundle(n00b_allocator_t *allocator)
{
    n00b_obj_bundle_t *bundle =
        new_default_exec_bundle_with_allocator(allocator);

    add_builtin_policy(bundle, 1, N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
    add_declarative_policy(
        bundle,
        2,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
        TEST_DECL_EXEC_DEFAULT,
        N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
            | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED,
        1,
        1);

    return bundle;
}

static n00b_buffer_t *
require_encode(n00b_obj_bundle_t *bundle)
{
    auto result = n00b_obj_bundle_encode(bundle);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    return n00b_result_get(result);
}

static n00b_obj_bundle_t *
require_decode(n00b_buffer_t *encoded)
{
    auto result = n00b_obj_bundle_decode(encoded);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    return n00b_result_get(result);
}

static n00b_obj_bundle_exec_plan_t *
require_exec_ok(n00b_result_t(n00b_obj_bundle_exec_plan_t *) result)
{
    N00B_TEST_REQUIRE(n00b_result_is_ok(result));

    n00b_obj_bundle_exec_plan_t *plan = n00b_result_get(result);

    N00B_TEST_REQUIRE(plan != nullptr);
    return plan;
}

static n00b_obj_bundle_error_t *
require_exec_error(n00b_result_t(n00b_obj_bundle_exec_plan_t *) result,
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
assert_pointer_allocator(void *ptr, n00b_allocator_t *expected)
{
    auto owner = n00b_find_allocator(ptr);

    N00B_TEST_REQUIRE(n00b_option_is_set(owner));
    N00B_TEST_REQUIRE(n00b_option_get(owner) == expected);
}

static void
assert_string_eq(n00b_string_t *actual, n00b_string_t *expected)
{
    N00B_TEST_REQUIRE(n00b_unicode_str_eq(actual, expected));
}

static void
assert_selected_target(n00b_obj_bundle_exec_plan_t              *plan,
                       uint64_t                                 expected_id,
                       n00b_string_t                           *expected_path,
                       n00b_obj_bundle_exec_selection_source_t   source)
{
    auto artifact_id = n00b_obj_bundle_exec_plan_selected_artifact_id(plan);
    auto logical_path =
        n00b_obj_bundle_exec_plan_selected_logical_path(plan);

    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_plan_selection_source(plan)
                      == source);
    N00B_TEST_REQUIRE(n00b_option_is_set(artifact_id));
    N00B_TEST_REQUIRE(n00b_option_get(artifact_id) == expected_id);
    N00B_TEST_REQUIRE(n00b_option_is_set(logical_path));
    assert_string_eq(n00b_option_get(logical_path), expected_path);
}

static void
assert_no_detail(n00b_obj_bundle_error_t *error)
{
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_error_detail(error)));
}

static void
assert_execution_scope(n00b_obj_bundle_error_t *error)
{
    auto scope = n00b_obj_bundle_error_policy_scope(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(scope));
    N00B_TEST_REQUIRE(n00b_option_get(scope)
                      == N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION);
}

static void
assert_exec_policy_facts_with_fallback(
    n00b_obj_bundle_exec_plan_t  *plan,
    n00b_obj_bundle_policy_kind_t expected_kind,
    bool                          expected_fallback)
{
    auto kind = n00b_obj_bundle_exec_plan_policy_kind(plan);
    auto scope = n00b_obj_bundle_exec_plan_policy_scope(plan);

    N00B_TEST_REQUIRE(n00b_option_is_set(kind));
    N00B_TEST_REQUIRE(n00b_option_get(kind) == expected_kind);
    N00B_TEST_REQUIRE(n00b_option_is_set(scope));
    N00B_TEST_REQUIRE(n00b_option_get(scope)
                      == N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION);
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_plan_fallback_used(plan)
                      == expected_fallback);
}

static void
assert_exec_policy_facts(n00b_obj_bundle_exec_plan_t  *plan,
                         n00b_obj_bundle_policy_kind_t expected_kind)
{
    assert_exec_policy_facts_with_fallback(plan, expected_kind, false);
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
                      == N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION);
}

static void
assert_detail(n00b_obj_bundle_error_t *error, int64_t expected)
{
    auto detail = n00b_obj_bundle_error_detail(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(detail));
    N00B_TEST_REQUIRE(n00b_option_get(detail) == expected);
}

static void
assert_error_logical_path(n00b_obj_bundle_error_t *error,
                          n00b_string_t          *expected)
{
    auto logical_path = n00b_obj_bundle_error_logical_path(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(logical_path));
    assert_string_eq(n00b_option_get(logical_path), expected);
}

static void
assert_error_artifact_id(n00b_obj_bundle_error_t *error,
                         uint64_t                 expected)
{
    auto artifact_id = n00b_obj_bundle_error_artifact_id(error);

    N00B_TEST_REQUIRE(n00b_option_is_set(artifact_id));
    N00B_TEST_REQUIRE(n00b_option_get(artifact_id) == expected);
}

static void
assert_no_exec_mode_context(n00b_obj_bundle_error_t *error)
{
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_error_exec_requested_mode(error)));
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_error_exec_platform_support(error)));
}

static n00b_obj_bundle_exec_argv_t *
require_plan_argv(n00b_obj_bundle_exec_plan_t *plan)
{
    auto argv_fact = n00b_obj_bundle_exec_plan_argv(plan);

    N00B_TEST_REQUIRE(n00b_option_is_set(argv_fact));
    return n00b_option_get(argv_fact);
}

static n00b_obj_bundle_exec_env_t *
require_plan_env(n00b_obj_bundle_exec_plan_t *plan)
{
    auto env_fact = n00b_obj_bundle_exec_plan_env(plan);

    N00B_TEST_REQUIRE(n00b_option_is_set(env_fact));
    return n00b_option_get(env_fact);
}

static void
assert_argv_entry(n00b_obj_bundle_exec_argv_t *argv,
                  size_t                       index,
                  n00b_string_t               *expected)
{
    N00B_TEST_REQUIRE(index < n00b_list_len(*argv));
    assert_string_eq(n00b_list_get(*argv, index), expected);
}

static void
assert_common_extracted_mode(n00b_obj_bundle_exec_plan_t *plan,
                             n00b_obj_bundle_exec_mode_t  requested)
{
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_plan_requested_mode(plan)
                      == requested);
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_plan_resolved_mode(plan)
                      == N00B_OBJ_BUNDLE_EXEC_EXTRACTED);
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_plan_platform_support(plan)
                      == N00B_OBJ_BUNDLE_EXEC_PLATFORM_SUPPORTED);
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_plan_requires_extraction(plan));
}

static void
assert_unsupported_mode_error(n00b_obj_bundle_error_t    *error,
                              n00b_obj_bundle_exec_mode_t mode)
{
    auto requested = n00b_obj_bundle_error_exec_requested_mode(error);
    auto support = n00b_obj_bundle_error_exec_platform_support(error);

    assert_execution_scope(error);
    assert_detail(error, mode);
    N00B_TEST_REQUIRE(n00b_option_is_set(requested));
    N00B_TEST_REQUIRE(n00b_option_get(requested) == mode);
    N00B_TEST_REQUIRE(n00b_option_is_set(support));
    N00B_TEST_REQUIRE(n00b_option_get(support)
                      == N00B_OBJ_BUNDLE_EXEC_PLATFORM_UNSUPPORTED);
}

static n00b_obj_bundle_exec_argv_t *
make_argv(void)
{
    n00b_obj_bundle_exec_argv_t *argv =
        n00b_alloc(n00b_obj_bundle_exec_argv_t);

    *argv = n00b_list_new(n00b_string_t *);
    n00b_list_push(*argv, r"custom-tool");
    n00b_list_push(*argv, r"--flag");

    return argv;
}

static n00b_obj_bundle_exec_env_t *
make_env(void)
{
    n00b_obj_bundle_exec_env_t *env =
        n00b_dict_new(n00b_string_t *, n00b_string_t *);
    n00b_string_t *key   = r"N00B_OBJ_BUNDLE_EXEC_PLAN_TEST_ENV_OVERLAY";
    n00b_string_t *value = r"overlay-value";

    n00b_dict_put(env, key, value);

    return env;
}

static void
assert_buffer_eq(n00b_buffer_t *actual, n00b_buffer_t *expected)
{
    N00B_TEST_REQUIRE(actual->byte_len == expected->byte_len);
    N00B_TEST_REQUIRE(memcmp(actual->data,
                             expected->data,
                             actual->byte_len) == 0);
}

static void
assert_env_value_unchanged(n00b_string_t *before, n00b_string_t *after)
{
    if (before == nullptr) {
        N00B_TEST_REQUIRE(after == nullptr);
        return;
    }

    N00B_TEST_REQUIRE(after != nullptr);
    assert_string_eq(after, before);
}

static void
test_default_controls(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();
    n00b_obj_bundle_exec_plan_t *plan =
        require_exec_ok(n00b_obj_bundle_exec_plan(bundle));

    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_exec_plan_selector(plan)));
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_exec_plan_env(plan)));
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_plan_inherit_env(plan));
    N00B_TEST_REQUIRE(!n00b_obj_bundle_exec_plan_strict_selector(plan));
    assert_common_extracted_mode(plan, N00B_OBJ_BUNDLE_EXEC_AUTO);
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_plan_policy_mode(plan)
                      == N00B_OBJ_BUNDLE_POLICY_ENFORCE);
    assert_exec_policy_facts(plan,
                             N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
    n00b_obj_bundle_exec_argv_t *planned_argv = require_plan_argv(plan);

    N00B_TEST_REQUIRE(n00b_list_len(*planned_argv) == 1);
    assert_argv_entry(planned_argv, 0, r"bin/default");
    assert_selected_target(plan,
                           0,
                           r"bin/default",
                           N00B_OBJ_BUNDLE_EXEC_SELECTION_DEFAULT);
}

static void
test_custom_controls_are_planned_and_reported(void)
{
    n00b_obj_bundle_t *bundle = new_selector_bundle();
    n00b_string_t     *selector = r"tool";
    n00b_obj_bundle_exec_argv_t *argv = make_argv();
    n00b_obj_bundle_exec_env_t  *env  = make_env();

    n00b_obj_bundle_exec_plan_t *plan = require_exec_ok(
        n00b_obj_bundle_exec_plan(
            bundle,
            .selector        = selector,
            .argv            = argv,
            .env             = env,
            .inherit_env     = false,
            .strict_selector = true,
            .mode            = N00B_OBJ_BUNDLE_EXEC_EXTRACTED,
            .policy_mode     = N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY));

    auto selector_fact = n00b_obj_bundle_exec_plan_selector(plan);

    N00B_TEST_REQUIRE(n00b_option_is_set(selector_fact));
    N00B_TEST_REQUIRE(n00b_option_get(selector_fact) == selector);
    assert_string_eq(n00b_option_get(selector_fact), r"tool");

    n00b_obj_bundle_exec_argv_t *planned_argv = require_plan_argv(plan);

    N00B_TEST_REQUIRE(planned_argv != argv);
    N00B_TEST_REQUIRE(n00b_list_len(*planned_argv) == 2);
    assert_argv_entry(planned_argv, 0, r"custom-tool");
    assert_argv_entry(planned_argv, 1, r"--flag");

    n00b_obj_bundle_exec_env_t *planned_env = require_plan_env(plan);
    bool found = false;
    n00b_string_t *key   = r"N00B_OBJ_BUNDLE_EXEC_PLAN_TEST_ENV_OVERLAY";
    n00b_string_t *value = n00b_dict_get(planned_env, key, &found);

    N00B_TEST_REQUIRE(planned_env != env);
    N00B_TEST_REQUIRE(found);
    assert_string_eq(value, r"overlay-value");

    n00b_list_push(*argv, r"--mutated-after-planning");
    n00b_string_t *mutated = r"mutated-overlay";
    n00b_dict_put(env, key, mutated);

    N00B_TEST_REQUIRE(n00b_list_len(*planned_argv) == 2);
    assert_argv_entry(planned_argv, 0, r"custom-tool");
    assert_argv_entry(planned_argv, 1, r"--flag");

    found = false;
    value = n00b_dict_get(planned_env, key, &found);
    N00B_TEST_REQUIRE(found);
    assert_string_eq(value, r"overlay-value");

    N00B_TEST_REQUIRE(!n00b_obj_bundle_exec_plan_inherit_env(plan));
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_plan_strict_selector(plan));
    assert_common_extracted_mode(plan, N00B_OBJ_BUNDLE_EXEC_EXTRACTED);
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_plan_policy_mode(plan)
                      == N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY);
    assert_exec_policy_facts(plan,
                             N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
    assert_selected_target(
        plan,
        1,
        r"bin/tool",
        N00B_OBJ_BUNDLE_EXEC_SELECTION_SELECTOR_MAPPING);
}

static void
test_declarative_policy_selection_facts(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();

    add_builtin_policy(bundle, 1, N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
    add_declarative_policy(bundle,
                           2,
                           N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
                           TEST_DECL_EXEC_DEFAULT,
                           N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
                           1,
                           N00B_OBJ_BUNDLE_POLICY_ID_NONE);

    n00b_obj_bundle_exec_plan_t *plan =
        require_exec_ok(n00b_obj_bundle_exec_plan(bundle));

    assert_exec_policy_facts(plan,
                             N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1);
    assert_selected_target(plan,
                           0,
                           r"bin/default",
                           N00B_OBJ_BUNDLE_EXEC_SELECTION_DEFAULT);
}

static void
test_unknown_optional_policy_uses_allowed_fallback(void)
{
    n00b_obj_bundle_t *bundle = new_exec_fallback_bundle(nullptr);
    test_obj_bundle_policy_t *declarative = test_policy_at(bundle, 1);

    declarative->kind = (n00b_obj_bundle_policy_kind_t)99;

    n00b_obj_bundle_exec_plan_t *plan =
        require_exec_ok(n00b_obj_bundle_exec_plan(bundle));

    assert_exec_policy_facts_with_fallback(
        plan,
        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
        true);
    assert_selected_target(plan,
                           0,
                           r"bin/default",
                           N00B_OBJ_BUNDLE_EXEC_SELECTION_DEFAULT);
}

static void
test_unknown_required_policy_rejects(void)
{
    n00b_obj_bundle_t *bundle = new_exec_fallback_bundle(nullptr);
    test_obj_bundle_policy_t *declarative = test_policy_at(bundle, 1);

    declarative->kind  = (n00b_obj_bundle_policy_kind_t)99;
    declarative->flags = N00B_OBJ_BUNDLE_POLICY_F_REQUIRED;

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle),
                           N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE);

    assert_error_policy(error, (n00b_obj_bundle_policy_kind_t)99);
    assert_detail(error, 2);
}

static void
test_embedded_policy_allows_default_execution(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();

    add_embedded_policy(bundle,
                        1,
                        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
                        N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
                        1,
                        N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                        n00b_buffer_from_cstr(
                            "arg.logical_path == \"bin/default\""));

    n00b_obj_bundle_exec_plan_t *plan =
        require_exec_ok(n00b_obj_bundle_exec_plan(bundle));

    assert_exec_policy_facts(plan,
                             N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);
    assert_selected_target(plan,
                           0,
                           r"bin/default",
                           N00B_OBJ_BUNDLE_EXEC_SELECTION_DEFAULT);
}

static void
test_embedded_policy_denies_default_execution(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();

    add_embedded_policy(bundle,
                        1,
                        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
                        N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
                        1,
                        N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                        n00b_buffer_from_cstr("false"));

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle),
                           N00B_OBJ_BUNDLE_ERR_POLICY_DENIED);

    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);
    assert_error_logical_path(error, r"bin/default");
    assert_error_artifact_id(error, 0);
}

static void
test_embedded_optional_compile_failure_uses_allowed_fallback(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();

    add_builtin_policy(bundle, 1, N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
    add_embedded_policy(
        bundle,
        2,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
        N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
            | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED,
        1,
        1,
        n00b_buffer_from_cstr(";"));

    n00b_obj_bundle_exec_plan_t *plan =
        require_exec_ok(n00b_obj_bundle_exec_plan(bundle));

    assert_exec_policy_facts_with_fallback(
        plan,
        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
        true);
    assert_selected_target(plan,
                           0,
                           r"bin/default",
                           N00B_OBJ_BUNDLE_EXEC_SELECTION_DEFAULT);
}

static void
test_embedded_required_compile_failure_rejects(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();

    add_embedded_policy(bundle,
                        1,
                        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
                        N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
                        1,
                        N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                        n00b_buffer_from_cstr(";"));

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle),
                           N00B_OBJ_BUNDLE_ERR_BUILD);

    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);
    assert_detail(error, TEST_N00B_EVAL_ERR_PARSE);
    assert_error_logical_path(error, r"bin/default");
    assert_error_artifact_id(error, 0);
}

static void
test_embedded_policy_denies_selector_mapping(void)
{
    n00b_obj_bundle_t *bundle = new_selector_bundle();

    add_embedded_policy(bundle,
                        1,
                        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
                        N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
                        1,
                        N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                        n00b_buffer_from_cstr(
                            "arg.selection_source == 1"));

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle,
                                                     .selector = r"tool"),
                           N00B_OBJ_BUNDLE_ERR_POLICY_DENIED);

    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);
    assert_error_logical_path(error, r"bin/tool");
    assert_error_artifact_id(error, 1);
}

static void
test_embedded_optional_false_validate_only_denies_without_fallback(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();

    add_builtin_policy(bundle, 1, N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
    add_embedded_policy(
        bundle,
        2,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
        N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
            | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED,
        1,
        1,
        n00b_buffer_from_cstr("false"));

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(
                               bundle,
                               .policy_mode =
                                   N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY),
                           N00B_OBJ_BUNDLE_ERR_POLICY_DENIED);

    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);
    assert_error_logical_path(error, r"bin/default");
    assert_error_artifact_id(error, 0);
}

static void
test_disallowed_fallback_rejects(void)
{
    n00b_obj_bundle_t *bundle = new_exec_fallback_bundle(nullptr);
    test_obj_bundle_policy_t *declarative = test_policy_at(bundle, 1);

    declarative->flags = N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL;

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle),
                           N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1);
    assert_detail(error, 1);
}

static void
test_incompatible_fallback_rejects(void)
{
    n00b_obj_bundle_t *bundle = new_exec_fallback_bundle(nullptr);
    test_obj_bundle_policy_t *builtin = test_policy_at(bundle, 0);

    builtin->priority = 5;

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle),
                           N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1);
    assert_detail(error, 1);
}

static void
test_default_exec_policy_denial(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();

    add_declarative_policy(
        bundle,
        1,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
        TEST_DECL_EXEC_SELECTOR_MAPPING,
        N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
        1,
        N00B_OBJ_BUNDLE_POLICY_ID_NONE);

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle),
                           N00B_OBJ_BUNDLE_ERR_POLICY_DENIED);

    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1);
    assert_detail(error, TEST_DECL_EXEC_DEFAULT_EXEC);
    assert_error_logical_path(error, r"bin/default");
    assert_error_artifact_id(error, 0);
    assert_no_exec_mode_context(error);
}

static void
test_selector_mapping_policy_denial_does_not_fall_back(void)
{
    n00b_obj_bundle_t *bundle = new_selector_bundle();

    add_declarative_policy(
        bundle,
        1,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
        TEST_DECL_EXEC_DEFAULT_EXEC,
        N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
        1,
        N00B_OBJ_BUNDLE_POLICY_ID_NONE);

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle,
                                                     .selector = r"tool"),
                           N00B_OBJ_BUNDLE_ERR_POLICY_DENIED);

    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1);
    assert_detail(error, TEST_DECL_EXEC_SELECTOR_MAPPING);
    assert_error_logical_path(error, r"tool");
    assert_error_artifact_id(error, 1);
    assert_no_exec_mode_context(error);
}

static void
test_validate_only_still_evaluates_policy_denial(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();

    add_declarative_policy(
        bundle,
        1,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
        TEST_DECL_EXEC_SELECTOR_MAPPING,
        N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
        1,
        N00B_OBJ_BUNDLE_POLICY_ID_NONE);

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(
                               bundle,
                               .policy_mode =
                                   N00B_OBJ_BUNDLE_POLICY_VALIDATE_ONLY),
                           N00B_OBJ_BUNDLE_ERR_POLICY_DENIED);

    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1);
    assert_detail(error, TEST_DECL_EXEC_DEFAULT_EXEC);
}

static void
test_policy_denial_precedes_mode_resolution(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();

    add_declarative_policy(
        bundle,
        1,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
        TEST_DECL_EXEC_SELECTOR_MAPPING,
        N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
        1,
        N00B_OBJ_BUNDLE_POLICY_ID_NONE);

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(
                               bundle,
                               .mode = N00B_OBJ_BUNDLE_EXEC_MEMFD),
                           N00B_OBJ_BUNDLE_ERR_POLICY_DENIED);

    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1);
    assert_detail(error, TEST_DECL_EXEC_DEFAULT_EXEC);
    assert_no_exec_mode_context(error);
}

static void
test_allocator_threaded_policy_error(void)
{
    n00b_arena_t *arena =
        n00b_new_arena(.size   = 32768,
                       .use_gc = false,
                       .name   = "test_obj_bundle_exec_policy");
    n00b_allocator_t *allocator = (n00b_allocator_t *)arena;
    n00b_obj_bundle_t *bundle = new_exec_fallback_bundle(nullptr);
    test_obj_bundle_policy_t *declarative = test_policy_at(bundle, 1);

    declarative->flags = N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL;

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle,
                                                     .allocator = allocator),
                           N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    assert_pointer_allocator(error, allocator);
    assert_error_policy(error, N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1);
    assert_detail(error, 1);

    n00b_allocator_destroy(allocator);
}

static void
test_invalid_null_bundle_error(void)
{
    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(nullptr),
                           N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    N00B_TEST_REQUIRE(n00b_option_is_set(
        n00b_obj_bundle_error_message(error)));
    assert_no_detail(error);
}

static void
test_invalid_policy_mode_error(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();
    n00b_obj_bundle_policy_mode_t invalid =
        (n00b_obj_bundle_policy_mode_t)99;
    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle,
                                                     .policy_mode = invalid),
                           N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    assert_execution_scope(error);
    assert_detail(error, 99);
}

static void
test_invalid_execution_mode_error(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();
    n00b_obj_bundle_exec_mode_t invalid =
        (n00b_obj_bundle_exec_mode_t)99;
    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle,
                                                     .mode = invalid),
                           N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    assert_execution_scope(error);
    assert_detail(error, 99);
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_error_exec_requested_mode(error)));
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_error_exec_platform_support(error)));
}

static void
test_unsupported_future_modes_report_context(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();

    n00b_obj_bundle_error_t *memfd =
        require_exec_error(n00b_obj_bundle_exec_plan(
                               bundle,
                               .mode = N00B_OBJ_BUNDLE_EXEC_MEMFD),
                           N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_EXEC_MODE);

    assert_unsupported_mode_error(memfd, N00B_OBJ_BUNDLE_EXEC_MEMFD);

    n00b_obj_bundle_error_t *entrypoint =
        require_exec_error(n00b_obj_bundle_exec_plan(
                               bundle,
                               .mode =
                                   N00B_OBJ_BUNDLE_EXEC_HOST_ENTRYPOINT),
                           N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_EXEC_MODE);

    assert_unsupported_mode_error(
        entrypoint,
        N00B_OBJ_BUNDLE_EXEC_HOST_ENTRYPOINT);
}

static void
test_allocator_threaded_payloads(void)
{
    n00b_arena_t *arena =
        n00b_new_arena(.size   = 32768,
                       .use_gc = false,
                       .name   = "test_obj_bundle_exec");
    n00b_allocator_t *allocator = (n00b_allocator_t *)arena;
    n00b_obj_bundle_t *bundle   = new_default_exec_bundle();

    n00b_obj_bundle_exec_plan_t *plan = require_exec_ok(
        n00b_obj_bundle_exec_plan(bundle, .allocator = allocator));
    assert_pointer_allocator(plan, allocator);
    assert_pointer_allocator(require_plan_argv(plan), allocator);

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(
                               bundle,
                               .mode = (n00b_obj_bundle_exec_mode_t)99,
                               .allocator = allocator),
                           N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);
    assert_pointer_allocator(error, allocator);

    n00b_obj_bundle_error_t *unsupported =
        require_exec_error(n00b_obj_bundle_exec_plan(
                               bundle,
                               .mode = N00B_OBJ_BUNDLE_EXEC_MEMFD,
                               .allocator = allocator),
                           N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_EXEC_MODE);
    assert_pointer_allocator(unsupported, allocator);
    assert_unsupported_mode_error(unsupported, N00B_OBJ_BUNDLE_EXEC_MEMFD);

    test_obj_bundle_shadow_t *shadow = shadow_bundle(bundle);

    shadow->default_exec_id = 99;
    n00b_obj_bundle_error_t *validation_error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle,
                                                     .allocator = allocator),
                           N00B_OBJ_BUNDLE_ERR_MISSING_TARGET);
    assert_pointer_allocator(validation_error, allocator);
    assert_execution_scope(validation_error);
    assert_error_artifact_id(validation_error, 99);

    n00b_allocator_destroy(allocator);
}

static void
test_environment_overlay_does_not_mutate_process_environment(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();
    n00b_obj_bundle_exec_env_t *env = make_env();
    n00b_string_t *name =
        r"N00B_OBJ_BUNDLE_EXEC_PLAN_TEST_ENV_OVERLAY";
    n00b_string_t *before = n00b_getenv(name);

    n00b_obj_bundle_exec_plan_t *plan = require_exec_ok(
        n00b_obj_bundle_exec_plan(bundle, .env = env));

    n00b_string_t *after = n00b_getenv(name);
    n00b_obj_bundle_exec_env_t *planned_env = require_plan_env(plan);
    bool found = false;
    n00b_string_t *value = n00b_dict_get(planned_env, name, &found);

    assert_env_value_unchanged(before, after);
    N00B_TEST_REQUIRE(n00b_obj_bundle_exec_plan_inherit_env(plan));
    N00B_TEST_REQUIRE(found);
    assert_string_eq(value, r"overlay-value");
}

static void
test_manifest_roundtrip_planning_preserves_execution_facts(void)
{
    n00b_obj_bundle_t *bundle = new_selector_bundle();

    add_builtin_policy(bundle, 1, N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
    add_declarative_policy(bundle,
                           2,
                           N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
                           TEST_DECL_EXEC_DEFAULT,
                           N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
                           1,
                           N00B_OBJ_BUNDLE_POLICY_ID_NONE);

    n00b_obj_bundle_exec_argv_t *argv = make_argv();
    n00b_buffer_t *encoded = require_encode(bundle);
    n00b_obj_bundle_t *decoded = require_decode(encoded);
    n00b_obj_bundle_exec_plan_t *original_plan = require_exec_ok(
        n00b_obj_bundle_exec_plan(bundle,
                                  .selector = r"tool",
                                  .argv = argv,
                                  .mode = N00B_OBJ_BUNDLE_EXEC_EXTRACTED));
    n00b_obj_bundle_exec_plan_t *decoded_plan = require_exec_ok(
        n00b_obj_bundle_exec_plan(decoded,
                                  .selector = r"tool",
                                  .argv = argv,
                                  .mode = N00B_OBJ_BUNDLE_EXEC_EXTRACTED));

    assert_selected_target(
        original_plan,
        1,
        r"bin/tool",
        N00B_OBJ_BUNDLE_EXEC_SELECTION_SELECTOR_MAPPING);
    assert_selected_target(
        decoded_plan,
        1,
        r"bin/tool",
        N00B_OBJ_BUNDLE_EXEC_SELECTION_SELECTOR_MAPPING);
    assert_common_extracted_mode(original_plan,
                                 N00B_OBJ_BUNDLE_EXEC_EXTRACTED);
    assert_common_extracted_mode(decoded_plan,
                                 N00B_OBJ_BUNDLE_EXEC_EXTRACTED);
    assert_exec_policy_facts(original_plan,
                             N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1);
    assert_exec_policy_facts(decoded_plan,
                             N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1);

    n00b_obj_bundle_exec_argv_t *planned_argv =
        require_plan_argv(decoded_plan);

    N00B_TEST_REQUIRE(n00b_list_len(*planned_argv) == 2);
    assert_argv_entry(planned_argv, 0, r"custom-tool");
    assert_argv_entry(planned_argv, 1, r"--flag");
    assert_buffer_eq(require_encode(decoded), encoded);
}

static void
test_embedded_manifest_roundtrip_preserves_execution_behavior(void)
{
    n00b_obj_bundle_t *bundle = new_selector_bundle();

    add_embedded_policy(bundle,
                        1,
                        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
                        N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
                        1,
                        N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                        n00b_buffer_from_cstr(
                            "arg.selection_source == 2"));

    n00b_buffer_t *encoded = require_encode(bundle);
    n00b_obj_bundle_t *decoded = require_decode(encoded);
    n00b_obj_bundle_exec_plan_t *decoded_plan = require_exec_ok(
        n00b_obj_bundle_exec_plan(decoded, .selector = r"tool"));

    assert_selected_target(
        decoded_plan,
        1,
        r"bin/tool",
        N00B_OBJ_BUNDLE_EXEC_SELECTION_SELECTOR_MAPPING);
    assert_exec_policy_facts(decoded_plan,
                             N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);
    assert_buffer_eq(require_encode(decoded), encoded);
}

static void
test_valid_plan_does_not_mutate_bundle(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();

    n00b_buffer_t *before = require_encode(bundle);

    n00b_obj_bundle_exec_plan_t *plan =
        require_exec_ok(n00b_obj_bundle_exec_plan(bundle));
    assert_selected_target(plan,
                           0,
                           r"bin/default",
                           N00B_OBJ_BUNDLE_EXEC_SELECTION_DEFAULT);

    n00b_buffer_t *after = require_encode(bundle);

    assert_buffer_eq(after, before);
}

static void
test_missing_selector_falls_back_to_default(void)
{
    n00b_obj_bundle_t *bundle = new_selector_bundle();

    n00b_obj_bundle_exec_plan_t *plan = require_exec_ok(
        n00b_obj_bundle_exec_plan(bundle, .selector = r"missing"));

    auto selector_fact = n00b_obj_bundle_exec_plan_selector(plan);

    N00B_TEST_REQUIRE(n00b_option_is_set(selector_fact));
    assert_string_eq(n00b_option_get(selector_fact), r"missing");
    n00b_obj_bundle_exec_argv_t *planned_argv = require_plan_argv(plan);

    N00B_TEST_REQUIRE(n00b_list_len(*planned_argv) == 1);
    assert_argv_entry(planned_argv, 0, r"bin/default");
    assert_selected_target(plan,
                           0,
                           r"bin/default",
                           N00B_OBJ_BUNDLE_EXEC_SELECTION_DEFAULT);
}

static void
test_strict_missing_selector_rejects(void)
{
    n00b_obj_bundle_t *bundle = new_selector_bundle();
    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle,
                                                     .selector = r"missing",
                                                     .strict_selector = true),
                           N00B_OBJ_BUNDLE_ERR_MISSING_TARGET);

    assert_execution_scope(error);
    assert_error_logical_path(error, r"missing");
}

static void
test_data_only_bundle_has_no_target(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();
    n00b_string_t     *path   = r"data/payload.txt";

    require_bool_ok(n00b_obj_bundle_add_artifact(bundle,
                                                 path,
                                                 payload_bytes(),
                                                 .kind =
                                                     N00B_OBJ_BUNDLE_ARTIFACT_FILE));

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle),
                           N00B_OBJ_BUNDLE_ERR_MISSING_TARGET);

    assert_execution_scope(error);
}

static void
test_mapping_without_default_requires_selector(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();
    n00b_string_t     *selector = r"tool";
    n00b_string_t     *path     = r"bin/tool";

    add_executable(bundle, path);
    require_bool_ok(n00b_obj_bundle_add_exec_mapping(bundle, selector, path));

    n00b_obj_bundle_error_t *no_selector =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle),
                           N00B_OBJ_BUNDLE_ERR_MISSING_TARGET);

    assert_execution_scope(no_selector);

    n00b_obj_bundle_exec_plan_t *plan = require_exec_ok(
        n00b_obj_bundle_exec_plan(bundle, .selector = selector));

    n00b_obj_bundle_exec_argv_t *planned_argv = require_plan_argv(plan);

    N00B_TEST_REQUIRE(n00b_list_len(*planned_argv) == 1);
    assert_argv_entry(planned_argv, 0, r"bin/tool");
    assert_selected_target(
        plan,
        0,
        r"bin/tool",
        N00B_OBJ_BUNDLE_EXEC_SELECTION_SELECTOR_MAPPING);
}

static void
test_file_mode_executable_selection(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();
    n00b_string_t     *path   = r"bin/script";

    require_bool_ok(n00b_obj_bundle_add_artifact(bundle,
                                                 path,
                                                 payload_bytes(),
                                                 .mode = 0755));
    require_bool_ok(n00b_obj_bundle_set_default_exec(bundle, path));

    n00b_obj_bundle_exec_plan_t *plan =
        require_exec_ok(n00b_obj_bundle_exec_plan(bundle));

    assert_selected_target(plan,
                           0,
                           r"bin/script",
                           N00B_OBJ_BUNDLE_EXEC_SELECTION_DEFAULT);
}

static void
test_missing_default_target_rejects_with_artifact_context(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();
    test_obj_bundle_shadow_t *shadow = shadow_bundle(bundle);

    shadow->default_exec_id = 99;

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle),
                           N00B_OBJ_BUNDLE_ERR_MISSING_TARGET);

    assert_execution_scope(error);
    assert_error_artifact_id(error, 99);
}

static void
test_missing_mapping_target_rejects_with_artifact_context(void)
{
    n00b_obj_bundle_t *bundle = new_selector_bundle();
    test_obj_bundle_shadow_t *shadow = shadow_bundle(bundle);

    N00B_TEST_REQUIRE(shadow->exec_mappings.len == 1);
    shadow->exec_mappings.data[0]->target_artifact_id = 99;

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle,
                                                     .selector = r"tool"),
                           N00B_OBJ_BUNDLE_ERR_MISSING_TARGET);

    assert_execution_scope(error);
    assert_error_artifact_id(error, 99);
}

static void
test_non_executable_target_rejects(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();
    test_obj_bundle_shadow_t *shadow = shadow_bundle(bundle);
    n00b_string_t *path = r"data/payload.txt";

    require_bool_ok(n00b_obj_bundle_add_artifact(bundle,
                                                 path,
                                                 payload_bytes(),
                                                 .kind =
                                                     N00B_OBJ_BUNDLE_ARTIFACT_FILE));

    shadow->has_default_exec = true;
    shadow->default_exec_id  = 0;

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle),
                           N00B_OBJ_BUNDLE_ERR_MISSING_TARGET);

    assert_execution_scope(error);
    assert_error_artifact_id(error, 0);
}

static void
test_duplicate_selector_rejects_before_selection(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();
    test_obj_bundle_shadow_t *shadow = shadow_bundle(bundle);
    n00b_string_t *selector_a = r"a";
    n00b_string_t *selector_b = r"b";
    n00b_string_t *path_a     = r"bin/a";
    n00b_string_t *path_b     = r"bin/b";

    add_executable(bundle, path_a);
    add_executable(bundle, path_b);
    require_bool_ok(n00b_obj_bundle_add_exec_mapping(bundle,
                                                     selector_a,
                                                     path_a));
    require_bool_ok(n00b_obj_bundle_add_exec_mapping(bundle,
                                                     selector_b,
                                                     path_b));

    N00B_TEST_REQUIRE(shadow->exec_mappings.len == 2);
    shadow->exec_mappings.data[1]->selector =
        shadow->exec_mappings.data[0]->selector;

    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle,
                                                     .selector = selector_a),
                           N00B_OBJ_BUNDLE_ERR_DUPLICATE_SELECTOR);

    assert_execution_scope(error);
}

static void
test_invalid_selector_argument_rejects(void)
{
    n00b_obj_bundle_t *bundle = new_default_exec_bundle();
    n00b_obj_bundle_error_t *error =
        require_exec_error(n00b_obj_bundle_exec_plan(bundle,
                                                     .selector = r""),
                           N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    assert_execution_scope(error);
    assert_error_logical_path(error, r"");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_default_controls();
    test_custom_controls_are_planned_and_reported();
    test_declarative_policy_selection_facts();
    test_unknown_optional_policy_uses_allowed_fallback();
    test_unknown_required_policy_rejects();
    test_embedded_policy_allows_default_execution();
    test_embedded_policy_denies_default_execution();
    test_embedded_optional_compile_failure_uses_allowed_fallback();
    test_embedded_required_compile_failure_rejects();
    test_embedded_policy_denies_selector_mapping();
    test_embedded_optional_false_validate_only_denies_without_fallback();
    test_disallowed_fallback_rejects();
    test_incompatible_fallback_rejects();
    test_default_exec_policy_denial();
    test_selector_mapping_policy_denial_does_not_fall_back();
    test_validate_only_still_evaluates_policy_denial();
    test_policy_denial_precedes_mode_resolution();
    test_allocator_threaded_policy_error();
    test_invalid_null_bundle_error();
    test_invalid_policy_mode_error();
    test_invalid_execution_mode_error();
    test_unsupported_future_modes_report_context();
    test_allocator_threaded_payloads();
    test_environment_overlay_does_not_mutate_process_environment();
    test_manifest_roundtrip_planning_preserves_execution_facts();
    test_embedded_manifest_roundtrip_preserves_execution_behavior();
    test_valid_plan_does_not_mutate_bundle();
    test_missing_selector_falls_back_to_default();
    test_strict_missing_selector_rejects();
    test_data_only_bundle_has_no_target();
    test_mapping_without_default_requires_selector();
    test_file_mode_executable_selection();
    test_missing_default_target_rejects_with_artifact_context();
    test_missing_mapping_target_rejects_with_artifact_context();
    test_non_executable_target_rejects();
    test_duplicate_selector_rejects_before_selection();
    test_invalid_selector_argument_rejects();

    return 0;
}
