#include "n00b.h"
#include "core/gc.h"
#include "core/runtime.h"
#include "core/sha256.h"
#include "core/stw.h"
#include "util/assert.h"
#include "compiler/objfile/obj_bundle.h"

#define N00B_TEST_REQUIRE(expr) n00b_require((expr), #expr)

#define TEST_MANIFEST_HEADER_SIZE    208u
#define TEST_CONTENT_ID_OFF          32u
#define TEST_ARTIFACT_COUNT_OFF      64u
#define TEST_PAYLOAD_COUNT_OFF       72u
#define TEST_EXEC_COUNT_OFF          80u
#define TEST_POLICY_COUNT_OFF        88u
#define TEST_ARTIFACT_TABLE_OFF      96u
#define TEST_PAYLOAD_TABLE_OFF       112u
#define TEST_EXEC_TABLE_OFF          128u
#define TEST_POLICY_TABLE_OFF        144u
#define TEST_STRING_TABLE_OFF        160u
#define TEST_PAYLOAD_AREA_OFF        176u
#define TEST_EXTENSION_TABLE_OFF     192u
#define TEST_ARTIFACT_REC_SIZE       72u
#define TEST_PAYLOAD_REC_SIZE        64u
#define TEST_EXEC_REC_SIZE           24u
#define TEST_POLICY_REC_SIZE         88u
#define TEST_EXEC_REC_DEFAULT        1u
#define TEST_EXEC_REC_SELECTOR       2u
#define TEST_DECL_POLICY_SIZE        64u
#define TEST_DECL_POLICY_DECL_FLAGS_OFF       16u
#define TEST_DECL_POLICY_PATH_FLAGS_OFF       24u
#define TEST_DECL_POLICY_ARTIFACT_MASK_OFF    32u
#define TEST_DECL_POLICY_EXEC_FLAGS_OFF       40u
#define TEST_DECL_POLICY_FALLBACK_ID_OFF      48u
#define TEST_DECL_POLICY_RESERVED1_OFF        56u
#define TEST_EMBEDDED_POLICY_COMPAT_FLAGS_OFF 16u
#define TEST_EMBEDDED_POLICY_FALLBACK_ID_OFF  24u
#define TEST_EMBEDDED_POLICY_SOURCE_LEN_OFF   32u
#define TEST_EMBEDDED_POLICY_RESERVED1_OFF    40u

static n00b_buffer_t *
test_cached_buffer(n00b_buffer_t **cache, const char *data, size_t len)
{
    if (*cache == nullptr) {
        *cache = n00b_buffer_from_bytes((char *)data, (int64_t)len);
    }

    return *cache;
}

#define TEST_LITERAL_BUFFER(name, literal)              \
    static n00b_buffer_t *                              \
    test_##name(void)                                   \
    {                                                   \
        static n00b_buffer_t *cache = nullptr;          \
        return test_cached_buffer(&cache,               \
                                  (literal),            \
                                  sizeof(literal) - 1); \
    }

TEST_LITERAL_BUFFER(payload_bytes, "payload")
TEST_LITERAL_BUFFER(tool_bytes, "tool")
TEST_LITERAL_BUFFER(x_bytes, "x")
TEST_LITERAL_BUFFER(late_bytes, "late")
TEST_LITERAL_BUFFER(script_bytes, "script")
TEST_LITERAL_BUFFER(policy_bytes,
                    "N00BPOL1\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00"
                    "\x1f\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00"
                    "\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00"
                    "\x00\x00\x00\x00\x00\x00")
TEST_LITERAL_BUFFER(embedded_source_bytes, "bundle.allow")
TEST_LITERAL_BUFFER(empty_source_bytes, "")
TEST_LITERAL_BUFFER(bad_bytes, "bad")

#define payload_bytes test_payload_bytes()
#define tool_bytes test_tool_bytes()
#define x_bytes test_x_bytes()
#define late_bytes test_late_bytes()
#define script_bytes test_script_bytes()
#define policy_bytes test_policy_bytes()
#define embedded_source_bytes test_embedded_source_bytes()
#define empty_source_bytes test_empty_source_bytes()
#define bad_bytes test_bad_bytes()

static n00b_obj_bundle_t *
new_bundle(void)
{
    auto create = n00b_obj_bundle_new();

    N00B_TEST_REQUIRE(n00b_result_is_ok(create));
    return n00b_result_get(create);
}

static n00b_obj_bundle_error_t *
require_bool_error(n00b_result_t(bool) result,
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

static n00b_buffer_t *
require_encode(n00b_obj_bundle_t *bundle)
{
    auto result = n00b_obj_bundle_encode(bundle);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    return n00b_result_get(result);
}

static n00b_obj_bundle_error_t *
require_encode_error(n00b_result_t(n00b_buffer_t *) result,
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

static n00b_obj_bundle_t *
require_decode(n00b_buffer_t *encoded)
{
    auto result = n00b_obj_bundle_decode(encoded);

    N00B_TEST_REQUIRE(n00b_result_is_ok(result));
    return n00b_result_get(result);
}

static n00b_obj_bundle_error_t *
require_decode_error(n00b_result_t(n00b_obj_bundle_t *) result,
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

static uint16_t
read_le16(const uint8_t *data, size_t off)
{
    return (uint16_t)data[off] | ((uint16_t)data[off + 1] << 8);
}

static uint32_t
read_le32(const uint8_t *data, size_t off)
{
    return (uint32_t)data[off]
           | ((uint32_t)data[off + 1] << 8)
           | ((uint32_t)data[off + 2] << 16)
           | ((uint32_t)data[off + 3] << 24);
}

static uint64_t
read_le64(const uint8_t *data, size_t off)
{
    return (uint64_t)read_le32(data, off)
           | ((uint64_t)read_le32(data, off + 4) << 32);
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
    n00b_buffer_t *payload =
        n00b_buffer_from_bytes((char *)policy_bytes->data,
                               (int64_t)policy_bytes->byte_len);

    write_le64((uint8_t *)payload->data,
               TEST_DECL_POLICY_FALLBACK_ID_OFF,
               fallback_policy_id);

    return payload;
}

static n00b_buffer_t *
make_embedded_policy_payload(uint64_t             fallback_policy_id,
                             const n00b_buffer_t *source)
{
    size_t len = N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF
                 + source->byte_len;
    n00b_buffer_t *payload = n00b_buffer_new((int64_t)len);
    uint8_t       *data    = (uint8_t *)payload->data;

    memset(data, 0, len);
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
               (uint64_t)source->byte_len);
    memcpy(data + N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF,
           source->data,
           source->byte_len);

    return payload;
}

static void
sha256_bytes(const void *data, size_t len, uint8_t out[32])
{
    n00b_sha256_digest_t digest;

    n00b_sha256_hash(data, len, digest);

    for (size_t i = 0; i < N00B_SHA256_DIGEST_WORDS; i++) {
        uint32_t word = digest[i];

        out[i * 4]     = (uint8_t)(word >> 24);
        out[i * 4 + 1] = (uint8_t)(word >> 16);
        out[i * 4 + 2] = (uint8_t)(word >> 8);
        out[i * 4 + 3] = (uint8_t)word;
    }
}

static void
assert_content_id(n00b_buffer_t *encoded)
{
    n00b_buffer_t *copy = n00b_buffer_copy(encoded);
    uint8_t        digest[32];

    memset(copy->data + TEST_CONTENT_ID_OFF, 0, N00B_OBJ_BUNDLE_CONTENT_ID_LEN);
    sha256_bytes(copy->data, copy->byte_len, digest);
    N00B_TEST_REQUIRE(memcmp(encoded->data + TEST_CONTENT_ID_OFF,
                             digest,
                             sizeof(digest)) == 0);
}

static void
update_content_id(n00b_buffer_t *encoded)
{
    uint8_t *data = (uint8_t *)encoded->data;
    uint8_t  digest[32];

    memset(data + TEST_CONTENT_ID_OFF, 0, N00B_OBJ_BUNDLE_CONTENT_ID_LEN);
    sha256_bytes(data, encoded->byte_len, digest);
    memcpy(data + TEST_CONTENT_ID_OFF, digest, sizeof(digest));
}

static void
assert_digest_at(const uint8_t      *data,
                 uint64_t            off,
                 const n00b_buffer_t *expected)
{
    uint8_t digest[32];

    sha256_bytes(expected->data, expected->byte_len, digest);
    N00B_TEST_REQUIRE(memcmp(data + off, digest, sizeof(digest)) == 0);
}

static void
assert_zero_digest_at(const uint8_t *data, uint64_t off)
{
    for (size_t i = 0; i < N00B_OBJ_BUNDLE_DIGEST_LEN; i++) {
        N00B_TEST_REQUIRE(data[off + i] == 0);
    }
}

static uint64_t
policy_record_at(const uint8_t *data, uint64_t policy_index)
{
    return read_le64(data, TEST_POLICY_TABLE_OFF)
           + policy_index * TEST_POLICY_REC_SIZE;
}

static uint8_t *
policy_payload_at(n00b_buffer_t *encoded, uint64_t policy_index)
{
    uint8_t *data = (uint8_t *)encoded->data;
    uint64_t policy_rec = policy_record_at(data, policy_index);
    uint64_t area_off = read_le64(data, TEST_PAYLOAD_AREA_OFF);
    uint64_t payload_off = read_le64(data, policy_rec + 32);

    return data + area_off + payload_off;
}

static void
update_policy_payload_digest(n00b_buffer_t *encoded, uint64_t policy_index)
{
    uint8_t *data = (uint8_t *)encoded->data;
    uint64_t policy_rec = policy_record_at(data, policy_index);
    uint64_t area_off = read_le64(data, TEST_PAYLOAD_AREA_OFF);
    uint64_t payload_off = read_le64(data, policy_rec + 32);
    uint64_t payload_len = read_le64(data, policy_rec + 40);
    uint8_t  digest[32];

    sha256_bytes(data + area_off + payload_off, payload_len, digest);
    memcpy(data + policy_rec + 56, digest, sizeof(digest));
}

static void
assert_string_at(const uint8_t *data,
                 uint64_t       string_off,
                 uint64_t       string_len,
                 uint32_t       off,
                 n00b_string_t *expected)
{
    N00B_TEST_REQUIRE(off < string_len);

    size_t len = 0;

    while ((uint64_t)off + len < string_len
           && data[string_off + off + len] != 0) {
        len++;
    }

    N00B_TEST_REQUIRE((uint64_t)off + len < string_len);
    N00B_TEST_REQUIRE(len == expected->u8_bytes);
    N00B_TEST_REQUIRE(memcmp(data + string_off + off,
                             expected->data,
                             expected->u8_bytes) == 0);
}

static n00b_obj_bundle_t *
make_encoded_bundle(bool reverse)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    if (reverse) {
        auto add_data = n00b_obj_bundle_add_artifact(bundle,
                                                     r"share/data",
                                                     payload_bytes);
        N00B_TEST_REQUIRE(n00b_result_is_ok(add_data));

        auto add_exec = n00b_obj_bundle_add_artifact(
            bundle,
            r"bin/tool",
            tool_bytes,
            .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
            .role = r"primary",
            .mode = 0755);
        N00B_TEST_REQUIRE(n00b_result_is_ok(add_exec));
    }
    else {
        auto add_exec = n00b_obj_bundle_add_artifact(
            bundle,
            r"bin/tool",
            tool_bytes,
            .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
            .role = r"primary",
            .mode = 0755);
        N00B_TEST_REQUIRE(n00b_result_is_ok(add_exec));

        auto add_data = n00b_obj_bundle_add_artifact(bundle,
                                                     r"share/data",
                                                     payload_bytes);
        N00B_TEST_REQUIRE(n00b_result_is_ok(add_data));
    }

    auto set_default = n00b_obj_bundle_set_default_exec(bundle, r"bin/tool");
    N00B_TEST_REQUIRE(n00b_result_is_ok(set_default));

    auto map = n00b_obj_bundle_add_exec_mapping(bundle, r"run", r"bin/tool");
    N00B_TEST_REQUIRE(n00b_result_is_ok(map));

    if (reverse) {
        auto declarative = n00b_obj_bundle_add_policy(
            bundle,
            2,
            N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1,
            N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
            .flags   = N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL,
            .payload = policy_bytes);
        N00B_TEST_REQUIRE(n00b_result_is_ok(declarative));

        auto builtin = n00b_obj_bundle_add_policy(
            bundle,
            1,
            N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
            N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
        N00B_TEST_REQUIRE(n00b_result_is_ok(builtin));
    }
    else {
        auto builtin = n00b_obj_bundle_add_policy(
            bundle,
            1,
            N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
            N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
        N00B_TEST_REQUIRE(n00b_result_is_ok(builtin));

        auto declarative = n00b_obj_bundle_add_policy(
            bundle,
            2,
            N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1,
            N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
            .flags   = N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL,
            .payload = policy_bytes);
        N00B_TEST_REQUIRE(n00b_result_is_ok(declarative));
    }

    return bundle;
}

static void
test_manifest_constants(void)
{
    const uint8_t manifest_magic[N00B_OBJ_BUNDLE_MANIFEST_MAGIC_LEN] = {
        'N', '0', '0', 'B', 'N', 'D', 'L', '1',
    };
    const uint8_t policy_magic[N00B_OBJ_BUNDLE_POLICY_MAGIC_LEN] = {
        'N', '0', '0', 'B', 'P', 'O', 'L', '1',
    };
    const uint8_t embedded_magic[
        N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC_LEN] = {
        'N', '0', '0', 'B', 'E', 'P', 'O', 'L',
    };

    N00B_TEST_REQUIRE(N00B_OBJ_BUNDLE_MANIFEST_MAJOR == 1);
    N00B_TEST_REQUIRE(N00B_OBJ_BUNDLE_MANIFEST_MINOR == 0);
    N00B_TEST_REQUIRE(N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAJOR == 1);
    N00B_TEST_REQUIRE(N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MINOR == 0);
    N00B_TEST_REQUIRE(N00B_OBJ_BUNDLE_EMBEDDED_POLICY_HEADER_SIZE == 48);
    N00B_TEST_REQUIRE(N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF == 48);
    N00B_TEST_REQUIRE(
        N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SUPPORTED_COMPAT_FLAGS == 0);
    N00B_TEST_REQUIRE(N00B_OBJ_BUNDLE_CONTENT_ID_LEN == 32);
    N00B_TEST_REQUIRE(N00B_OBJ_BUNDLE_DIGEST_LEN == 32);

    for (size_t i = 0; i < N00B_OBJ_BUNDLE_MANIFEST_MAGIC_LEN; i++) {
        N00B_TEST_REQUIRE(N00B_OBJ_BUNDLE_MANIFEST_MAGIC[i]
                          == manifest_magic[i]);
    }

    for (size_t i = 0; i < N00B_OBJ_BUNDLE_POLICY_MAGIC_LEN; i++) {
        N00B_TEST_REQUIRE(N00B_OBJ_BUNDLE_POLICY_MAGIC[i] == policy_magic[i]);
    }

    for (size_t i = 0; i < N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC_LEN; i++) {
        N00B_TEST_REQUIRE(N00B_OBJ_BUNDLE_EMBEDDED_POLICY_MAGIC[i]
                          == embedded_magic[i]);
    }

    const uint8_t *policy_data = (const uint8_t *)policy_bytes->data;

    N00B_TEST_REQUIRE(policy_bytes->byte_len == TEST_DECL_POLICY_SIZE);
    N00B_TEST_REQUIRE(memcmp(policy_data,
                             N00B_OBJ_BUNDLE_POLICY_MAGIC,
                             N00B_OBJ_BUNDLE_POLICY_MAGIC_LEN) == 0);
    N00B_TEST_REQUIRE(read_le16(policy_data, 8) == 1);
    N00B_TEST_REQUIRE(read_le16(policy_data, 10) == 0);
    N00B_TEST_REQUIRE(read_le32(policy_data, 12) == 0);
    N00B_TEST_REQUIRE(read_le64(policy_data,
                                TEST_DECL_POLICY_DECL_FLAGS_OFF) == 0);
    N00B_TEST_REQUIRE(read_le64(policy_data,
                                TEST_DECL_POLICY_PATH_FLAGS_OFF) == 0x1f);
    N00B_TEST_REQUIRE(read_le64(policy_data,
                                TEST_DECL_POLICY_ARTIFACT_MASK_OFF) == 0x1f);
    N00B_TEST_REQUIRE(read_le64(policy_data,
                                TEST_DECL_POLICY_EXEC_FLAGS_OFF) == 0x03);
    N00B_TEST_REQUIRE(read_le64(policy_data,
                                TEST_DECL_POLICY_FALLBACK_ID_OFF)
                      == N00B_OBJ_BUNDLE_POLICY_ID_NONE);
    N00B_TEST_REQUIRE(read_le64(policy_data,
                                TEST_DECL_POLICY_RESERVED1_OFF) == 0);
}

static void
test_construction_and_validation(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();
    N00B_TEST_REQUIRE(bundle != nullptr);

    auto strict = n00b_obj_bundle_validate(bundle);
    N00B_TEST_REQUIRE(n00b_result_is_ok(strict));
    N00B_TEST_REQUIRE(n00b_result_get(strict) == true);

    auto relaxed = n00b_obj_bundle_validate(bundle, .strict = false);
    N00B_TEST_REQUIRE(n00b_result_is_ok(relaxed));
    N00B_TEST_REQUIRE(n00b_result_get(relaxed) == true);
}

static void
test_structured_error_payload(void)
{
    auto result = n00b_obj_bundle_validate(nullptr);

    N00B_TEST_REQUIRE(n00b_result_is_err(result));
    N00B_TEST_REQUIRE(
        n00b_result_is_err_payload(n00b_obj_bundle_error_t *, result));

    n00b_obj_bundle_error_t *error =
        n00b_result_get_err_payload(n00b_obj_bundle_error_t *, result);

    N00B_TEST_REQUIRE(n00b_obj_bundle_error_code(error)
                      == N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    auto message = n00b_obj_bundle_error_message(error);
    N00B_TEST_REQUIRE(n00b_option_is_set(message));
    N00B_TEST_REQUIRE(n00b_option_get(message) != nullptr);

    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_error_format(error)));
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_error_carrier(error)));
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_error_logical_path(error)));
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_error_artifact_id(error)));
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_error_policy_kind(error)));
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_error_policy_scope(error)));
    N00B_TEST_REQUIRE(!n00b_option_is_set(
        n00b_obj_bundle_error_detail(error)));

    N00B_TEST_REQUIRE(
        n00b_obj_bundle_err_str(N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT)
        != nullptr);
    N00B_TEST_REQUIRE(n00b_obj_bundle_err_str(-999999) != nullptr);
}

static void
test_logical_path_validation(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();
    n00b_string_t     *bad_paths[] = {
        r"",
        r"/absolute",
        r"nested//empty",
        r"nested/.",
        r"nested/..",
        r"nested/trailing/",
    };

    for (size_t i = 0; i < sizeof(bad_paths) / sizeof(bad_paths[0]); i++) {
        n00b_obj_bundle_error_t *error = require_bool_error(
            n00b_obj_bundle_add_artifact(bundle,
                                         bad_paths[i],
                                         payload_bytes),
            N00B_OBJ_BUNDLE_ERR_INVALID_LOGICAL_PATH);

        N00B_TEST_REQUIRE(n00b_option_is_set(
            n00b_obj_bundle_error_logical_path(error)));
    }

    char          invalid_bytes[] = {(char)0xc0, (char)0xaf};
    n00b_string_t invalid_path    = {
        .data       = invalid_bytes,
        .u8_bytes   = sizeof(invalid_bytes),
        .codepoints = 0,
        .styling    = nullptr,
    };

    require_bool_error(
        n00b_obj_bundle_add_artifact(bundle, &invalid_path, payload_bytes),
        N00B_OBJ_BUNDLE_ERR_INVALID_LOGICAL_PATH);

    auto add =
        n00b_obj_bundle_add_artifact(bundle, r"valid/path", payload_bytes);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add));

    auto validate = n00b_obj_bundle_validate(bundle);
    N00B_TEST_REQUIRE(n00b_result_is_ok(validate));
}

static void
test_artifact_duplicates_and_payload_rules(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add = n00b_obj_bundle_add_artifact(bundle,
                                            r"bin/tool",
                                            tool_bytes,
                                            .kind =
                                                N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE,
                                            .role = r"primary",
                                            .mode = 0755);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add));

    require_bool_error(
        n00b_obj_bundle_add_artifact(bundle,
                                     r"bin/tool",
                                     x_bytes),
        N00B_OBJ_BUNDLE_ERR_DUPLICATE_LOGICAL_PATH);

    require_bool_error(
        n00b_obj_bundle_add_artifact(bundle,
                                     r"dir/with-bytes",
                                     x_bytes,
                                     .kind =
                                         N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY),
        N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    auto dir = n00b_obj_bundle_add_artifact(bundle,
                                            r"assets",
                                            nullptr,
                                            .kind =
                                                N00B_OBJ_BUNDLE_ARTIFACT_DIRECTORY);
    N00B_TEST_REQUIRE(n00b_result_is_ok(dir));

    auto validate = n00b_obj_bundle_validate(bundle);
    N00B_TEST_REQUIRE(n00b_result_is_ok(validate));
}

static void
test_exec_mapping_validation_and_atomicity(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    require_bool_error(n00b_obj_bundle_set_default_exec(
                           bundle,
                           r"bin/missing"),
                       N00B_OBJ_BUNDLE_ERR_MISSING_TARGET);

    auto add_exec = n00b_obj_bundle_add_artifact(
        bundle,
        r"bin/tool",
        tool_bytes,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_exec));

    auto set_default =
        n00b_obj_bundle_set_default_exec(bundle, r"bin/tool");
    N00B_TEST_REQUIRE(n00b_result_is_ok(set_default));

    require_bool_error(n00b_obj_bundle_set_default_exec(bundle, r"bin/tool"),
                       N00B_OBJ_BUNDLE_ERR_MULTIPLE_DEFAULT_EXEC);

    auto map = n00b_obj_bundle_add_exec_mapping(bundle,
                                                r"run",
                                                r"bin/tool");
    N00B_TEST_REQUIRE(n00b_result_is_ok(map));

    require_bool_error(n00b_obj_bundle_add_exec_mapping(bundle,
                                                        r"run",
                                                        r"bin/tool"),
                       N00B_OBJ_BUNDLE_ERR_DUPLICATE_SELECTOR);

    require_bool_error(n00b_obj_bundle_add_exec_mapping(bundle,
                                                        r"late",
                                                        r"bin/late"),
                       N00B_OBJ_BUNDLE_ERR_MISSING_TARGET);

    auto late_exec = n00b_obj_bundle_add_artifact(
        bundle,
        r"bin/late",
        late_bytes,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE);
    N00B_TEST_REQUIRE(n00b_result_is_ok(late_exec));

    auto late_map = n00b_obj_bundle_add_exec_mapping(bundle,
                                                     r"late",
                                                     r"bin/late");
    N00B_TEST_REQUIRE(n00b_result_is_ok(late_map));

    auto add_file = n00b_obj_bundle_add_artifact(bundle,
                                                 r"bin/script",
                                                 script_bytes,
                                                 .mode = 0755);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_file));

    auto file_map = n00b_obj_bundle_add_exec_mapping(bundle,
                                                     r"script",
                                                     r"bin/script");
    N00B_TEST_REQUIRE(n00b_result_is_ok(file_map));

    auto validate = n00b_obj_bundle_validate(bundle);
    N00B_TEST_REQUIRE(n00b_result_is_ok(validate));
}

static void
test_policy_records(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto builtin = n00b_obj_bundle_add_policy(
        bundle,
        1,
        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
    N00B_TEST_REQUIRE(n00b_result_is_ok(builtin));

    require_bool_error(n00b_obj_bundle_add_policy(
                           bundle,
                           1,
                           N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
                           N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH),
                       N00B_OBJ_BUNDLE_ERR_DUPLICATE_POLICY_ID);

    auto declarative = n00b_obj_bundle_add_policy(
        bundle,
        2,
        N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
        .flags   = N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL,
        .payload = policy_bytes);
    N00B_TEST_REQUIRE(n00b_result_is_ok(declarative));

    require_bool_error(n00b_obj_bundle_add_policy(
                           bundle,
                           3,
                           N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
                           N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION,
                           .payload = bad_bytes),
                       N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    require_bool_error(n00b_obj_bundle_add_policy(
                           bundle,
                           4,
                           N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1,
                           N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
                           .flags   = N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL,
                           .payload = bad_bytes),
                       N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    n00b_buffer_t *fallback_payload = make_policy_payload(1);

    auto with_fallback = n00b_obj_bundle_add_policy(
        bundle,
        5,
        N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
        .flags = N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
                 | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED,
        .priority = 1,
        .payload = fallback_payload,
        .fallback_policy_id = 1);
    N00B_TEST_REQUIRE(n00b_result_is_ok(with_fallback));

    n00b_buffer_t *bad_fallback_payload = make_policy_payload(2);

    require_bool_error(n00b_obj_bundle_add_policy(
                           bundle,
                           6,
                           N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1,
                           N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION,
                           .flags = N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
                                    | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED,
                           .priority = 1,
                           .payload = bad_fallback_payload,
                           .fallback_policy_id = 2),
                       N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    n00b_buffer_t *embedded_payload =
        make_embedded_policy_payload(N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                                     embedded_source_bytes);
    auto embedded_required = n00b_obj_bundle_add_policy(
        bundle,
        7,
        N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_EXTRACTION,
        .payload = embedded_payload);
    N00B_TEST_REQUIRE(n00b_result_is_ok(embedded_required));

    n00b_buffer_t *embedded_fallback_payload =
        make_embedded_policy_payload(1, embedded_source_bytes);
    auto embedded_with_fallback = n00b_obj_bundle_add_policy(
        bundle,
        8,
        N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH,
        .flags = N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
                 | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED,
        .priority = 1,
        .payload = embedded_fallback_payload,
        .fallback_policy_id = 1);
    N00B_TEST_REQUIRE(n00b_result_is_ok(embedded_with_fallback));

    auto validate = n00b_obj_bundle_validate(bundle);
    N00B_TEST_REQUIRE(n00b_result_is_ok(validate));
}

static void
require_embedded_policy_rejected(n00b_buffer_t *payload,
                                 uint64_t       flags,
                                 uint64_t       fallback_policy_id)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto builtin = n00b_obj_bundle_add_policy(
        bundle,
        1,
        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
    N00B_TEST_REQUIRE(n00b_result_is_ok(builtin));

    require_bool_error(n00b_obj_bundle_add_policy(
                           bundle,
                           2,
                           N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B,
                           N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH,
                           .flags = flags,
                           .priority = 1,
                           .payload = payload,
                           .fallback_policy_id = fallback_policy_id),
                       N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);
}

static void
test_embedded_policy_payload_validation(void)
{
    {
        n00b_buffer_t *payload =
            make_embedded_policy_payload(N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                                         embedded_source_bytes);

        ((uint8_t *)payload->data)[0] ^= 0x01u;
        require_embedded_policy_rejected(
            payload,
            N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
            N00B_OBJ_BUNDLE_POLICY_ID_NONE);
    }

    {
        n00b_buffer_t *payload =
            make_embedded_policy_payload(N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                                         embedded_source_bytes);

        write_le16((uint8_t *)payload->data, 8, 2);
        require_embedded_policy_rejected(
            payload,
            N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
            N00B_OBJ_BUNDLE_POLICY_ID_NONE);
    }

    {
        n00b_buffer_t *payload =
            make_embedded_policy_payload(N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                                         embedded_source_bytes);

        write_le32((uint8_t *)payload->data, 12, 1);
        require_embedded_policy_rejected(
            payload,
            N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
            N00B_OBJ_BUNDLE_POLICY_ID_NONE);
    }

    {
        n00b_buffer_t *payload =
            make_embedded_policy_payload(N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                                         embedded_source_bytes);

        write_le64((uint8_t *)payload->data,
                   TEST_EMBEDDED_POLICY_COMPAT_FLAGS_OFF,
                   1);
        require_embedded_policy_rejected(
            payload,
            N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
            N00B_OBJ_BUNDLE_POLICY_ID_NONE);
    }

    {
        n00b_buffer_t *payload =
            make_embedded_policy_payload(N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                                         embedded_source_bytes);

        write_le64((uint8_t *)payload->data,
                   TEST_EMBEDDED_POLICY_FALLBACK_ID_OFF,
                   99);
        require_embedded_policy_rejected(
            payload,
            N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
                | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED,
            1);
    }

    {
        n00b_buffer_t *payload =
            make_embedded_policy_payload(N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                                         empty_source_bytes);

        require_embedded_policy_rejected(
            payload,
            N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
            N00B_OBJ_BUNDLE_POLICY_ID_NONE);
    }

    {
        n00b_buffer_t *payload =
            make_embedded_policy_payload(N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                                         embedded_source_bytes);

        uint8_t *data = (uint8_t *)payload->data;

        data[N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF] = 0xffu;
        require_embedded_policy_rejected(
            payload,
            N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
            N00B_OBJ_BUNDLE_POLICY_ID_NONE);
    }

    {
        n00b_buffer_t *payload =
            make_embedded_policy_payload(N00B_OBJ_BUNDLE_POLICY_ID_NONE,
                                         embedded_source_bytes);

        write_le64((uint8_t *)payload->data,
                   TEST_EMBEDDED_POLICY_RESERVED1_OFF,
                   1);
        require_embedded_policy_rejected(
            payload,
            N00B_OBJ_BUNDLE_POLICY_F_REQUIRED,
            N00B_OBJ_BUNDLE_POLICY_ID_NONE);
    }
}

static n00b_obj_bundle_t *
make_embedded_policy_bundle(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto builtin = n00b_obj_bundle_add_policy(
        bundle,
        1,
        N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
    N00B_TEST_REQUIRE(n00b_result_is_ok(builtin));

    n00b_buffer_t *embedded_payload =
        make_embedded_policy_payload(1, embedded_source_bytes);
    auto embedded = n00b_obj_bundle_add_policy(
        bundle,
        2,
        N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B,
        N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH,
        .flags = N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
                 | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED,
        .priority = 2,
        .payload = embedded_payload,
        .fallback_policy_id = 1);
    N00B_TEST_REQUIRE(n00b_result_is_ok(embedded));

    return bundle;
}

static n00b_buffer_t *
make_embedded_canonical_encoded_bytes(void)
{
    return require_encode(make_embedded_policy_bundle());
}

static void
test_embedded_policy_encode_decode_round_trip(void)
{
    n00b_buffer_t *expected_payload =
        make_embedded_policy_payload(1, embedded_source_bytes);
    n00b_buffer_t *encoded = make_embedded_canonical_encoded_bytes();
    const uint8_t *data    = (const uint8_t *)encoded->data;
    uint64_t       policy1 = policy_record_at(data, 1);
    uint8_t       *payload = policy_payload_at(encoded, 1);

    N00B_TEST_REQUIRE(read_le64(data, policy1) == 2);
    N00B_TEST_REQUIRE(read_le32(data, policy1 + 8)
                      == N00B_OBJ_BUNDLE_POLICY_KIND_EMBEDDED_N00B);
    N00B_TEST_REQUIRE(read_le32(data, policy1 + 12)
                      == N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
    N00B_TEST_REQUIRE(read_le64(data, policy1 + 16)
                      == (N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
                          | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED));
    N00B_TEST_REQUIRE(read_le64(data, policy1 + 24) == 2);
    N00B_TEST_REQUIRE(read_le64(data, policy1 + 48) == 1);
    N00B_TEST_REQUIRE(read_le64(data, policy1 + 40)
                      == expected_payload->byte_len);
    assert_digest_at(data, policy1 + 56, expected_payload);
    N00B_TEST_REQUIRE(memcmp(payload,
                             expected_payload->data,
                             expected_payload->byte_len) == 0);

    n00b_obj_bundle_t *decoded   = require_decode(encoded);
    n00b_buffer_t     *reencoded = require_encode(decoded);

    N00B_TEST_REQUIRE(reencoded->byte_len == encoded->byte_len);
    N00B_TEST_REQUIRE(memcmp(reencoded->data,
                             encoded->data,
                             encoded->byte_len) == 0);
}

static void
test_decode_embedded_policy_payload_schema_errors(void)
{
    {
        n00b_buffer_t *encoded = make_embedded_canonical_encoded_bytes();
        uint8_t       *payload = policy_payload_at(encoded, 1);

        payload[0] ^= 0x01u;
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_embedded_canonical_encoded_bytes();
        uint8_t       *payload = policy_payload_at(encoded, 1);

        write_le16(payload, 8, 2);
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_embedded_canonical_encoded_bytes();
        uint8_t       *payload = policy_payload_at(encoded, 1);

        write_le32(payload, 12, 1);
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_embedded_canonical_encoded_bytes();
        uint8_t       *payload = policy_payload_at(encoded, 1);

        write_le64(payload, TEST_EMBEDDED_POLICY_COMPAT_FLAGS_OFF, 1);
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_embedded_canonical_encoded_bytes();
        uint8_t       *payload = policy_payload_at(encoded, 1);

        write_le64(payload, TEST_EMBEDDED_POLICY_FALLBACK_ID_OFF, 99);
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_embedded_canonical_encoded_bytes();
        uint8_t       *payload = policy_payload_at(encoded, 1);

        write_le64(payload, TEST_EMBEDDED_POLICY_SOURCE_LEN_OFF, 0);
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_embedded_canonical_encoded_bytes();
        uint8_t       *payload = policy_payload_at(encoded, 1);

        payload[N00B_OBJ_BUNDLE_EMBEDDED_POLICY_SOURCE_OFF] = 0xffu;
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_embedded_canonical_encoded_bytes();
        uint8_t       *payload = policy_payload_at(encoded, 1);

        write_le64(payload, TEST_EMBEDDED_POLICY_RESERVED1_OFF, 1);
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }
}

static void
test_encode_header_and_content_id(void)
{
    n00b_obj_bundle_t *bundle  = make_encoded_bundle(false);
    n00b_buffer_t     *encoded = require_encode(bundle);
    const uint8_t     *data    = (const uint8_t *)encoded->data;
    size_t             len     = encoded->byte_len;

    N00B_TEST_REQUIRE(len >= TEST_MANIFEST_HEADER_SIZE);
    N00B_TEST_REQUIRE(memcmp(data,
                             N00B_OBJ_BUNDLE_MANIFEST_MAGIC,
                             N00B_OBJ_BUNDLE_MANIFEST_MAGIC_LEN) == 0);
    N00B_TEST_REQUIRE(read_le16(data, 8) == N00B_OBJ_BUNDLE_MANIFEST_MAJOR);
    N00B_TEST_REQUIRE(read_le16(data, 10) == N00B_OBJ_BUNDLE_MANIFEST_MINOR);
    N00B_TEST_REQUIRE(read_le32(data, 12) == TEST_MANIFEST_HEADER_SIZE);
    N00B_TEST_REQUIRE(read_le64(data, 16) == len);
    N00B_TEST_REQUIRE(read_le64(data, 24) == 0);
    N00B_TEST_REQUIRE(read_le64(data, TEST_ARTIFACT_COUNT_OFF) == 2);
    N00B_TEST_REQUIRE(read_le64(data, TEST_PAYLOAD_COUNT_OFF) == 2);
    N00B_TEST_REQUIRE(read_le64(data, TEST_EXEC_COUNT_OFF) == 2);
    N00B_TEST_REQUIRE(read_le64(data, TEST_POLICY_COUNT_OFF) == 2);

    uint64_t artifact_off = read_le64(data, TEST_ARTIFACT_TABLE_OFF);
    uint64_t artifact_len = read_le64(data, TEST_ARTIFACT_TABLE_OFF + 8);
    uint64_t payload_off  = read_le64(data, TEST_PAYLOAD_TABLE_OFF);
    uint64_t payload_len  = read_le64(data, TEST_PAYLOAD_TABLE_OFF + 8);
    uint64_t exec_off     = read_le64(data, TEST_EXEC_TABLE_OFF);
    uint64_t exec_len     = read_le64(data, TEST_EXEC_TABLE_OFF + 8);
    uint64_t policy_off   = read_le64(data, TEST_POLICY_TABLE_OFF);
    uint64_t policy_len   = read_le64(data, TEST_POLICY_TABLE_OFF + 8);
    uint64_t string_off   = read_le64(data, TEST_STRING_TABLE_OFF);
    uint64_t string_len   = read_le64(data, TEST_STRING_TABLE_OFF + 8);
    uint64_t area_off     = read_le64(data, TEST_PAYLOAD_AREA_OFF);
    uint64_t area_len     = read_le64(data, TEST_PAYLOAD_AREA_OFF + 8);
    uint64_t ext_off      = read_le64(data, TEST_EXTENSION_TABLE_OFF);
    uint64_t ext_len      = read_le64(data, TEST_EXTENSION_TABLE_OFF + 8);

    N00B_TEST_REQUIRE(artifact_off == TEST_MANIFEST_HEADER_SIZE);
    N00B_TEST_REQUIRE(artifact_len == 2 * TEST_ARTIFACT_REC_SIZE);
    N00B_TEST_REQUIRE(payload_len == 2 * TEST_PAYLOAD_REC_SIZE);
    N00B_TEST_REQUIRE(exec_len == 2 * TEST_EXEC_REC_SIZE);
    N00B_TEST_REQUIRE(policy_len == 2 * TEST_POLICY_REC_SIZE);
    N00B_TEST_REQUIRE(payload_off >= artifact_off + artifact_len);
    N00B_TEST_REQUIRE(exec_off >= payload_off + payload_len);
    N00B_TEST_REQUIRE(policy_off >= exec_off + exec_len);
    N00B_TEST_REQUIRE(string_off >= policy_off + policy_len);
    N00B_TEST_REQUIRE(area_off >= string_off + string_len);
    N00B_TEST_REQUIRE(ext_off == area_off + area_len);
    N00B_TEST_REQUIRE(ext_len == 0);
    N00B_TEST_REQUIRE(ext_off == len);
    N00B_TEST_REQUIRE(data[string_off] == 0);
    N00B_TEST_REQUIRE(string_len > 1);
    N00B_TEST_REQUIRE(area_len == tool_bytes->byte_len
                                 + payload_bytes->byte_len
                                 + policy_bytes->byte_len);

    bool content_id_nonzero = false;

    for (size_t i = 0; i < N00B_OBJ_BUNDLE_CONTENT_ID_LEN; i++) {
        content_id_nonzero =
            content_id_nonzero || data[TEST_CONTENT_ID_OFF + i] != 0;
    }

    N00B_TEST_REQUIRE(content_id_nonzero);
    assert_content_id(encoded);
}

static void
test_encode_records(void)
{
    n00b_obj_bundle_t *bundle  = make_encoded_bundle(false);
    n00b_buffer_t     *encoded = require_encode(bundle);
    const uint8_t     *data    = (const uint8_t *)encoded->data;

    uint64_t artifact_off = read_le64(data, TEST_ARTIFACT_TABLE_OFF);
    uint64_t payload_off  = read_le64(data, TEST_PAYLOAD_TABLE_OFF);
    uint64_t exec_off     = read_le64(data, TEST_EXEC_TABLE_OFF);
    uint64_t policy_off   = read_le64(data, TEST_POLICY_TABLE_OFF);
    uint64_t string_off   = read_le64(data, TEST_STRING_TABLE_OFF);
    uint64_t string_len   = read_le64(data, TEST_STRING_TABLE_OFF + 8);
    uint64_t area_off     = read_le64(data, TEST_PAYLOAD_AREA_OFF);

    uint64_t artifact0 = artifact_off;
    uint64_t artifact1 = artifact_off + TEST_ARTIFACT_REC_SIZE;

    N00B_TEST_REQUIRE(read_le64(data, artifact0) == 0);
    N00B_TEST_REQUIRE(read_le32(data, artifact0 + 8)
                      == N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE);
    N00B_TEST_REQUIRE(read_le32(data, artifact0 + 12) == 0);
    N00B_TEST_REQUIRE(read_le64(data, artifact0 + 16) == 0);
    assert_string_at(data,
                     string_off,
                     string_len,
                     read_le32(data, artifact0 + 24),
                     r"bin/tool");
    assert_string_at(data,
                     string_off,
                     string_len,
                     read_le32(data, artifact0 + 28),
                     r"primary");
    N00B_TEST_REQUIRE(read_le32(data, artifact0 + 32) == 0755);
    N00B_TEST_REQUIRE(read_le32(data, artifact0 + 36) == 0);
    assert_digest_at(data, artifact0 + 40, tool_bytes);

    N00B_TEST_REQUIRE(read_le64(data, artifact1) == 1);
    N00B_TEST_REQUIRE(read_le32(data, artifact1 + 8)
                      == N00B_OBJ_BUNDLE_ARTIFACT_FILE);
    N00B_TEST_REQUIRE(read_le32(data, artifact1 + 12) == 0);
    N00B_TEST_REQUIRE(read_le64(data, artifact1 + 16) == 0);
    assert_string_at(data,
                     string_off,
                     string_len,
                     read_le32(data, artifact1 + 24),
                     r"share/data");
    N00B_TEST_REQUIRE(read_le32(data, artifact1 + 28) == 0);
    N00B_TEST_REQUIRE(read_le32(data, artifact1 + 32) == 0);
    N00B_TEST_REQUIRE(read_le32(data, artifact1 + 36) == 1);
    assert_digest_at(data, artifact1 + 40, payload_bytes);

    uint64_t payload0 = payload_off;
    uint64_t payload1 = payload_off + TEST_PAYLOAD_REC_SIZE;

    N00B_TEST_REQUIRE(read_le64(data, payload0) == 0);
    N00B_TEST_REQUIRE(read_le64(data, payload0 + 8) == 0);
    N00B_TEST_REQUIRE(read_le64(data, payload0 + 16) == 0);
    N00B_TEST_REQUIRE(read_le64(data, payload0 + 24) == tool_bytes->byte_len);
    assert_digest_at(data, payload0 + 32, tool_bytes);

    N00B_TEST_REQUIRE(read_le64(data, payload1) == 1);
    N00B_TEST_REQUIRE(read_le64(data, payload1 + 8) == 0);
    N00B_TEST_REQUIRE(read_le64(data, payload1 + 16) == tool_bytes->byte_len);
    N00B_TEST_REQUIRE(read_le64(data, payload1 + 24)
                      == payload_bytes->byte_len);
    assert_digest_at(data, payload1 + 32, payload_bytes);

    uint64_t exec0 = exec_off;
    uint64_t exec1 = exec_off + TEST_EXEC_REC_SIZE;

    N00B_TEST_REQUIRE(read_le32(data, exec0) == TEST_EXEC_REC_DEFAULT);
    N00B_TEST_REQUIRE(read_le32(data, exec0 + 4) == 0);
    N00B_TEST_REQUIRE(read_le32(data, exec0 + 8) == 0);
    N00B_TEST_REQUIRE(read_le32(data, exec0 + 12) == 0);
    N00B_TEST_REQUIRE(read_le64(data, exec0 + 16) == 0);

    N00B_TEST_REQUIRE(read_le32(data, exec1) == TEST_EXEC_REC_SELECTOR);
    N00B_TEST_REQUIRE(read_le32(data, exec1 + 4) == 0);
    assert_string_at(data,
                     string_off,
                     string_len,
                     read_le32(data, exec1 + 8),
                     r"run");
    N00B_TEST_REQUIRE(read_le32(data, exec1 + 12) == 0);
    N00B_TEST_REQUIRE(read_le64(data, exec1 + 16) == 0);

    uint64_t policy0 = policy_off;
    uint64_t policy1 = policy_off + TEST_POLICY_REC_SIZE;

    N00B_TEST_REQUIRE(read_le64(data, policy0) == 1);
    N00B_TEST_REQUIRE(read_le32(data, policy0 + 8)
                      == N00B_OBJ_BUNDLE_POLICY_KIND_BUILTIN_DEFAULT);
    N00B_TEST_REQUIRE(read_le32(data, policy0 + 12)
                      == N00B_OBJ_BUNDLE_POLICY_SCOPE_BOTH);
    N00B_TEST_REQUIRE(read_le64(data, policy0 + 16)
                      == N00B_OBJ_BUNDLE_POLICY_F_REQUIRED);
    N00B_TEST_REQUIRE(read_le64(data, policy0 + 24) == 0);
    N00B_TEST_REQUIRE(read_le64(data, policy0 + 32) == 0);
    N00B_TEST_REQUIRE(read_le64(data, policy0 + 40) == 0);
    N00B_TEST_REQUIRE(read_le64(data, policy0 + 48)
                      == N00B_OBJ_BUNDLE_POLICY_ID_NONE);
    assert_zero_digest_at(data, policy0 + 56);

    N00B_TEST_REQUIRE(read_le64(data, policy1) == 2);
    N00B_TEST_REQUIRE(read_le32(data, policy1 + 8)
                      == N00B_OBJ_BUNDLE_POLICY_KIND_DECLARATIVE_V1);
    N00B_TEST_REQUIRE(read_le32(data, policy1 + 12)
                      == N00B_OBJ_BUNDLE_POLICY_SCOPE_EXECUTION);
    N00B_TEST_REQUIRE(read_le64(data, policy1 + 16)
                      == N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL);
    N00B_TEST_REQUIRE(read_le64(data, policy1 + 24) == 0);
    N00B_TEST_REQUIRE(read_le64(data, policy1 + 32)
                      == tool_bytes->byte_len + payload_bytes->byte_len);
    N00B_TEST_REQUIRE(read_le64(data, policy1 + 40)
                      == policy_bytes->byte_len);
    N00B_TEST_REQUIRE(read_le64(data, policy1 + 48)
                      == N00B_OBJ_BUNDLE_POLICY_ID_NONE);
    assert_digest_at(data, policy1 + 56, policy_bytes);

    N00B_TEST_REQUIRE(memcmp(data + area_off,
                             tool_bytes->data,
                             tool_bytes->byte_len) == 0);
    N00B_TEST_REQUIRE(memcmp(data + area_off + tool_bytes->byte_len,
                             payload_bytes->data,
                             payload_bytes->byte_len) == 0);
    N00B_TEST_REQUIRE(memcmp(data + area_off + tool_bytes->byte_len
                                 + payload_bytes->byte_len,
                             policy_bytes->data,
                             policy_bytes->byte_len) == 0);
}

static void
test_encode_is_canonical_and_deterministic(void)
{
    n00b_obj_bundle_t *forward = make_encoded_bundle(false);
    n00b_obj_bundle_t *again   = make_encoded_bundle(false);
    n00b_obj_bundle_t *reverse = make_encoded_bundle(true);

    n00b_buffer_t *forward_bytes = require_encode(forward);
    n00b_buffer_t *again_bytes   = require_encode(again);
    n00b_buffer_t *reverse_bytes = require_encode(reverse);

    N00B_TEST_REQUIRE(forward_bytes->byte_len == again_bytes->byte_len);
    N00B_TEST_REQUIRE(forward_bytes->byte_len == reverse_bytes->byte_len);
    N00B_TEST_REQUIRE(memcmp(forward_bytes->data,
                             again_bytes->data,
                             forward_bytes->byte_len) == 0);
    N00B_TEST_REQUIRE(memcmp(forward_bytes->data,
                             reverse_bytes->data,
                             forward_bytes->byte_len) == 0);
}

static void
test_encode_errors(void)
{
    require_encode_error(n00b_obj_bundle_encode(nullptr),
                         N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);
}

static n00b_buffer_t *
make_canonical_encoded_bytes(void)
{
    return require_encode(make_encoded_bundle(false));
}

static void
test_decode_round_trip(void)
{
    n00b_buffer_t     *encoded = make_canonical_encoded_bytes();
    n00b_obj_bundle_t *decoded = require_decode(encoded);
    n00b_buffer_t     *again   = require_encode(decoded);

    N00B_TEST_REQUIRE(again->byte_len == encoded->byte_len);
    N00B_TEST_REQUIRE(memcmp(again->data,
                             encoded->data,
                             encoded->byte_len) == 0);
}

static void
test_decode_header_errors(void)
{
    require_decode_error(n00b_obj_bundle_decode(nullptr),
                         N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;

        data[0] ^= 0xffu;
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;

        write_le16(data, 8, N00B_OBJ_BUNDLE_MANIFEST_MAJOR + 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_VERSION);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;
        uint64_t       artifact_off = read_le64(data, TEST_ARTIFACT_TABLE_OFF);

        write_le64(data, TEST_PAYLOAD_TABLE_OFF, artifact_off + 8);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;

        data[TEST_CONTENT_ID_OFF] ^= 0x01u;
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_DIGEST_MISMATCH);
    }
}

static void
test_decode_artifact_payload_errors(void)
{
    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;
        uint64_t       artifact_off = read_le64(data, TEST_ARTIFACT_TABLE_OFF);

        write_le64(data, artifact_off, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_NON_CANONICAL_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;
        uint64_t       artifact_off = read_le64(data, TEST_ARTIFACT_TABLE_OFF);
        uint32_t       first_path =
            read_le32(data, artifact_off + 24);

        write_le32(data,
                   artifact_off + TEST_ARTIFACT_REC_SIZE + 24,
                   first_path);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_DUPLICATE_LOGICAL_PATH);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;
        uint64_t       payload_off = read_le64(data, TEST_PAYLOAD_TABLE_OFF);
        uint64_t       area_len = read_le64(data, TEST_PAYLOAD_AREA_OFF + 8);

        write_le64(data, payload_off + 16, area_len);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_OUT_OF_BOUNDS);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;
        uint64_t       payload_off = read_le64(data, TEST_PAYLOAD_TABLE_OFF);

        write_le64(data, payload_off + 8, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;
        uint64_t       area_off = read_le64(data, TEST_PAYLOAD_AREA_OFF);

        data[area_off] ^= 0x7fu;
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_DIGEST_MISMATCH);
    }
}

static void
test_decode_exec_policy_errors(void)
{
    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;
        uint64_t       exec_off = read_le64(data, TEST_EXEC_TABLE_OFF);
        uint64_t       exec1 = exec_off + TEST_EXEC_REC_SIZE;

        write_le32(data, exec1, TEST_EXEC_REC_DEFAULT);
        write_le32(data, exec1 + 8, 0);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MULTIPLE_DEFAULT_EXEC);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;
        uint64_t       exec_off = read_le64(data, TEST_EXEC_TABLE_OFF);
        uint64_t       exec1 = exec_off + TEST_EXEC_REC_SIZE;
        uint32_t       selector_off = read_le32(data, exec1 + 8);

        write_le32(data, exec_off, TEST_EXEC_REC_SELECTOR);
        write_le32(data, exec_off + 8, selector_off);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_DUPLICATE_SELECTOR);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;
        uint64_t       exec_off = read_le64(data, TEST_EXEC_TABLE_OFF);

        write_le64(data, exec_off + TEST_EXEC_REC_SIZE + 16, 99);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MISSING_TARGET);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;
        uint64_t       policy_off = read_le64(data, TEST_POLICY_TABLE_OFF);

        write_le32(data, policy_off + 8, 99);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_UNSUPPORTED_FEATURE);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;
        uint64_t       policy_off = read_le64(data, TEST_POLICY_TABLE_OFF);

        write_le64(data, policy_off + TEST_POLICY_REC_SIZE, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_DUPLICATE_POLICY_ID);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;
        uint64_t       policy1 = policy_record_at(data, 1);
        uint8_t       *payload = policy_payload_at(encoded, 1);

        write_le64(data,
                   policy1 + 16,
                   N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
                       | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED);
        write_le64(data, policy1 + 48, 99);
        write_le64(payload, TEST_DECL_POLICY_FALLBACK_ID_OFF, 99);
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_INVALID_ARGUMENT);
    }
}

static void
test_decode_policy_payload_schema_errors(void)
{
    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *payload = policy_payload_at(encoded, 1);

        payload[0] ^= 0x01u;
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *payload = policy_payload_at(encoded, 1);

        write_le16(payload, 8, 2);
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *payload = policy_payload_at(encoded, 1);

        write_le64(payload, TEST_DECL_POLICY_DECL_FLAGS_OFF, 1);
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *payload = policy_payload_at(encoded, 1);

        write_le64(payload, TEST_DECL_POLICY_PATH_FLAGS_OFF, 0x1e);
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *payload = policy_payload_at(encoded, 1);

        write_le64(payload, TEST_DECL_POLICY_ARTIFACT_MASK_OFF, 0x3f);
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *payload = policy_payload_at(encoded, 1);

        write_le64(payload, TEST_DECL_POLICY_EXEC_FLAGS_OFF, 0x04);
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *payload = policy_payload_at(encoded, 1);

        write_le64(payload, TEST_DECL_POLICY_RESERVED1_OFF, 1);
        update_policy_payload_digest(encoded, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;
        uint64_t       policy1 = policy_record_at(data, 1);

        write_le64(data,
                   policy1 + 16,
                   N00B_OBJ_BUNDLE_POLICY_F_OPTIONAL
                       | N00B_OBJ_BUNDLE_POLICY_F_FALLBACK_ALLOWED);
        write_le64(data, policy1 + 48, 1);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }
}

static void
test_decode_string_errors(void)
{
    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;
        uint64_t       exec_off = read_le64(data, TEST_EXEC_TABLE_OFF);
        uint64_t       exec1 = exec_off + TEST_EXEC_REC_SIZE;
        uint64_t       string_off = read_le64(data, TEST_STRING_TABLE_OFF);
        uint32_t       selector_off = read_le32(data, exec1 + 8);

        data[string_off + selector_off] = 0xffu;
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }

    {
        n00b_buffer_t *encoded = make_canonical_encoded_bytes();
        uint8_t       *data    = (uint8_t *)encoded->data;
        uint64_t       artifact_off = read_le64(data, TEST_ARTIFACT_TABLE_OFF);
        uint64_t       string_len = read_le64(data, TEST_STRING_TABLE_OFF + 8);

        write_le32(data, artifact_off + 24, (uint32_t)string_len);
        update_content_id(encoded);
        require_decode_error(n00b_obj_bundle_decode(encoded),
                             N00B_OBJ_BUNDLE_ERR_MALFORMED_MANIFEST);
    }
}

[[gnu::noinline]] static n00b_obj_bundle_t *
make_gc_visibility_bundle(void)
{
    n00b_obj_bundle_t *bundle = new_bundle();

    auto add_data = n00b_obj_bundle_add_artifact(bundle,
                                                 r"gc/data",
                                                 payload_bytes);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_data));

    auto add_exec = n00b_obj_bundle_add_artifact(
        bundle,
        r"gc/tool",
        tool_bytes,
        .kind = N00B_OBJ_BUNDLE_ARTIFACT_EXECUTABLE);
    N00B_TEST_REQUIRE(n00b_result_is_ok(add_exec));

    auto map = n00b_obj_bundle_add_exec_mapping(bundle,
                                                r"gc-run",
                                                r"gc/tool");
    N00B_TEST_REQUIRE(n00b_result_is_ok(map));

    return bundle;
}

static void
test_gc_visibility(void)
{
    n00b_obj_bundle_t *bundle = make_gc_visibility_bundle();
    n00b_runtime_t    *rt     = n00b_get_runtime();

    n00b_stop_the_world();
    n00b_collect(rt->default_arena);
    n00b_restart_the_world();

    auto validate = n00b_obj_bundle_validate(bundle);
    N00B_TEST_REQUIRE(n00b_result_is_ok(validate));

    require_bool_error(
        n00b_obj_bundle_add_artifact(bundle,
                                     r"gc/data",
                                     x_bytes),
        N00B_OBJ_BUNDLE_ERR_DUPLICATE_LOGICAL_PATH);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    test_manifest_constants();
    test_construction_and_validation();
    test_structured_error_payload();
    test_logical_path_validation();
    test_artifact_duplicates_and_payload_rules();
    test_exec_mapping_validation_and_atomicity();
    test_policy_records();
    test_embedded_policy_payload_validation();
    test_encode_header_and_content_id();
    test_encode_records();
    test_embedded_policy_encode_decode_round_trip();
    test_encode_is_canonical_and_deterministic();
    test_encode_errors();
    test_decode_round_trip();
    test_decode_header_errors();
    test_decode_artifact_payload_errors();
    test_decode_exec_policy_errors();
    test_decode_policy_payload_schema_errors();
    test_decode_embedded_policy_payload_schema_errors();
    test_decode_string_errors();
    test_gc_visibility();

    return 0;
}
