#include <string.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/file.h"
#include "core/runtime.h"
#include "chalk/n00b_chalk.h"
#include "internal/chalk/mark_internal.h"
#include "internal/chalk/sidecar_internal.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/elf.h"
#include "compiler/objfile/elf_build.h"
#include "compiler/objfile/elf_rewrite.h"
#include "compiler/objfile/elf_types.h"
#include "util/path.h"
#include "util/assert.h"

#include "objfile_elf_casegen.h"

#define N00B_TEST_REQUIRE(expr) n00b_require((expr), #expr)
#define ASSERT_OK(r)          N00B_TEST_REQUIRE(!n00b_result_is_err(r))
#define ASSERT_ERR(r)         N00B_TEST_REQUIRE(n00b_result_is_err(r))

static n00b_elf_rewrite_metadata_request_t
chalk_mark_request(n00b_buffer_t *payload)
{
    return (n00b_elf_rewrite_metadata_request_t){
        .section_name   = r".chalk.mark",
        .payload        = payload,
        .file_alignment = 8,
        .section_type   = SHT_PROGBITS,
        .section_flags  = 0,
        .policy         = {
            .flags = N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION
                   | N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY,
        },
    };
}

static n00b_elf_rewrite_metadata_request_t
chalk_mark_overlay_fixture_request(n00b_buffer_t *payload)
{
    n00b_elf_rewrite_metadata_request_t request =
        chalk_mark_request(payload);

    request.policy.flags |= N00B_ELF_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY;
    return request;
}

static void
assert_buffer_eq(n00b_buffer_t *a, n00b_buffer_t *b)
{
    N00B_TEST_REQUIRE(a != nullptr);
    N00B_TEST_REQUIRE(b != nullptr);
    N00B_TEST_REQUIRE(a->byte_len == b->byte_len);
    N00B_TEST_REQUIRE(memcmp(a->data, b->data, a->byte_len) == 0);
}

static bool
buffer_eq(n00b_buffer_t *a, n00b_buffer_t *b)
{
    return a != nullptr
        && b != nullptr
        && a->byte_len == b->byte_len
        && memcmp(a->data, b->data, a->byte_len) == 0;
}

static bool
section_name_matches(n00b_string_t *name, n00b_string_t *expected)
{
    return name != nullptr
        && name->u8_bytes == expected->u8_bytes
        && memcmp(name->data, expected->data, expected->u8_bytes) == 0;
}

static n00b_buffer_t *
supported_unmarked_elf(void)
{
    n00b_buffer_t *buf = n00b_test_elf_minimal_exec(0x400080,
                                                    0,
                                                    0x400000,
                                                    256,
                                                    512,
                                                    true,
                                                    false,
                                                    true,
                                                    false);
    buf->byte_len = 395;
    return buf;
}

static n00b_buffer_t *
supported_unmarked_overlay_elf(void)
{
    return n00b_test_elf_minimal_exec(0x400080,
                                      0,
                                      0x400000,
                                      512,
                                      512,
                                      true,
                                      false,
                                      true,
                                      true);
}

static n00b_buffer_t *
append_fixture_overlay(n00b_buffer_t *base)
{
    const size_t overlay_size = 16;

    N00B_TEST_REQUIRE(base != nullptr);
    N00B_TEST_REQUIRE(base->byte_len <= (size_t)INT64_MAX - overlay_size);

    n00b_buffer_t *with_overlay =
        n00b_buffer_new((int64_t)(base->byte_len + overlay_size));
    memcpy(with_overlay->data, base->data, base->byte_len);

    uint8_t *out = (uint8_t *)with_overlay->data;
    for (size_t i = 0; i < overlay_size; i++) {
        out[base->byte_len + i] = (uint8_t)(0xb0 + i);
    }
    with_overlay->byte_len = base->byte_len + overlay_size;

    return with_overlay;
}

static n00b_elf_binary_t *
parse_elf_or_fail(n00b_buffer_t *buf)
{
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto            parsed = n00b_elf_parse(stream);

    ASSERT_OK(parsed);
    return n00b_result_get(parsed);
}

static void
assert_original_range_preserved(n00b_buffer_t *before,
                                n00b_buffer_t *after,
                                uint64_t       start,
                                uint64_t       end)
{
    N00B_TEST_REQUIRE(start <= end);
    N00B_TEST_REQUIRE(end <= before->byte_len);
    N00B_TEST_REQUIRE(end <= after->byte_len);
    N00B_TEST_REQUIRE(memcmp(before->data + start,
                             after->data + start,
                             (size_t)(end - start)) == 0);
}

static void
assert_overlay_bytes_preserved(n00b_buffer_t     *before,
                               n00b_buffer_t     *after,
                               n00b_elf_binary_t *bin)
{
    N00B_TEST_REQUIRE(bin->overlay != nullptr);
    N00B_TEST_REQUIRE(bin->overlay->byte_len <= before->byte_len);

    uint64_t overlay_size  = bin->overlay->byte_len;
    uint64_t overlay_start = before->byte_len - overlay_size;

    assert_original_range_preserved(before,
                                    after,
                                    overlay_start,
                                    before->byte_len);
    N00B_TEST_REQUIRE(memcmp(after->data + overlay_start,
                             bin->overlay->data,
                             (size_t)overlay_size) == 0);
}

static uint32_t
chalk_mark_count(n00b_buffer_t *buf)
{
    n00b_elf_binary_t *bin   = parse_elf_or_fail(buf);
    n00b_string_t     *name  = r".chalk.mark";
    uint32_t           count = 0;

    for (uint32_t i = 0; i < bin->num_sections; i++) {
        if (section_name_matches(bin->sections[i].name, name)) {
            count++;
        }
    }

    return count;
}

static bool
has_chalk_mark(n00b_buffer_t *buf)
{
    n00b_elf_binary_t *bin = parse_elf_or_fail(buf);

    return n00b_option_is_set(n00b_elf_section_by_name(bin, ".chalk.mark"));
}

static n00b_buffer_t *
chalk_mark_payload(n00b_buffer_t *buf)
{
    n00b_elf_binary_t *bin = parse_elf_or_fail(buf);
    n00b_option_t(n00b_elf_section_t *) sec_opt =
        n00b_elf_section_by_name(bin, ".chalk.mark");

    N00B_TEST_REQUIRE(n00b_option_is_set(sec_opt));
    n00b_elf_section_t *sec = n00b_option_get(sec_opt);

    N00B_TEST_REQUIRE(sec->content != nullptr);
    uint64_t mark_len = sec->size;
    if (mark_len == 0 || mark_len > sec->content->byte_len) {
        mark_len = sec->content->byte_len;
    }
    N00B_TEST_REQUIRE(mark_len <= (uint64_t)INT64_MAX);

    return n00b_buffer_from_bytes(sec->content->data, (int64_t)mark_len);
}

static void
assert_extract_hash(n00b_buffer_t *marked, n00b_buffer_t *expected_hash)
{
    auto extracted = n00b_chalk_elf_extract_buffer(marked);
    ASSERT_OK(extracted);
    n00b_chalk_extract_result_t *ex = n00b_result_get(extracted);

    bool           found    = false;
    n00b_string_t *hash_key = r"HASH";
    n00b_json_node_t *hash_node =
        (n00b_json_node_t *)n00b_dict_get(ex->mark, hash_key, &found);

    N00B_TEST_REQUIRE(found);
    N00B_TEST_REQUIRE(hash_node != nullptr);
    N00B_TEST_REQUIRE(hash_node->type == N00B_JSON_STRING);
    N00B_TEST_REQUIRE(hash_node->string != nullptr);

    n00b_string_t *observed = n00b_string_from_cstr(hash_node->string);
    n00b_string_t *expected = n00b_buffer_to_hex_str(expected_hash);

    N00B_TEST_REQUIRE(observed->u8_bytes == expected->u8_bytes);
    N00B_TEST_REQUIRE(memcmp(observed->data,
                             expected->data,
                             expected->u8_bytes) == 0);
}

static void
assert_extract_result_hash(n00b_chalk_extract_result_t *ex,
                           n00b_buffer_t               *expected_hash)
{
    bool              found    = false;
    n00b_string_t    *hash_key = r"HASH";
    n00b_json_node_t *hash_node =
        (n00b_json_node_t *)n00b_dict_get(ex->mark, hash_key, &found);

    N00B_TEST_REQUIRE(found);
    N00B_TEST_REQUIRE(hash_node != nullptr);
    N00B_TEST_REQUIRE(hash_node->type == N00B_JSON_STRING);
    N00B_TEST_REQUIRE(hash_node->string != nullptr);

    n00b_string_t *observed = n00b_string_from_cstr(hash_node->string);
    n00b_string_t *expected = n00b_buffer_to_hex_str(expected_hash);

    N00B_TEST_REQUIRE(observed->u8_bytes == expected->u8_bytes);
    N00B_TEST_REQUIRE(memcmp(observed->data,
                             expected->data,
                             expected->u8_bytes) == 0);
}

static bool
offset_is_planned(n00b_elf_rewrite_plan_t *plan, uint64_t offset)
{
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        n00b_elf_rewrite_patch_t *patch = &plan->patches.data[i];
        if (patch->file_offset <= offset && offset < patch->file_end) {
            return true;
        }
    }

    return false;
}

static void
assert_unplanned_bytes_preserved(n00b_buffer_t             *before,
                                 n00b_buffer_t             *after,
                                 n00b_elf_rewrite_plan_t   *plan)
{
    N00B_TEST_REQUIRE(before != nullptr);
    N00B_TEST_REQUIRE(after != nullptr);
    N00B_TEST_REQUIRE(plan != nullptr);

    uint64_t common = before->byte_len < after->byte_len
        ? before->byte_len
        : after->byte_len;
    uint64_t preserved = 0;

    for (uint64_t i = 0; i < common; i++) {
        if (offset_is_planned(plan, i)) {
            continue;
        }

        N00B_TEST_REQUIRE(before->data[i] == after->data[i]);
        preserved++;
    }

    N00B_TEST_REQUIRE(preserved > 0);
}

static void
write_file_or_fail(n00b_string_t *path, n00b_buffer_t *bytes)
{
    auto opened = n00b_file_open(path,
                                 .mode = N00B_FILE_W,
                                 .kind = N00B_FILE_KIND_STREAM);
    ASSERT_OK(opened);
    n00b_file_t *file = n00b_result_get(opened);

    auto written = n00b_file_write(file, bytes->data, bytes->byte_len);
    n00b_file_close(file);

    ASSERT_OK(written);
    N00B_TEST_REQUIRE(n00b_result_get(written) == bytes->byte_len);
}

static n00b_buffer_t *
read_file_or_fail(n00b_string_t *path)
{
    auto opened = n00b_file_open(path, .kind = N00B_FILE_KIND_MMAP);
    ASSERT_OK(opened);
    n00b_file_t *file = n00b_result_get(opened);

    auto mapped = n00b_file_as_buffer(file);
    ASSERT_OK(mapped);
    n00b_buffer_t *bytes = n00b_result_get(mapped);
    n00b_buffer_t *copy  =
        n00b_buffer_from_bytes(bytes->data, (int64_t)bytes->byte_len);

    n00b_file_close(file);
    return copy;
}

static n00b_string_t *
temp_elf_path(void)
{
    return n00b_new_temp_path(r"n00b-chalk-elf-", r".elf");
}

static void
unlink_file_or_fail(n00b_string_t *path)
{
    auto unlinked = n00b_file_unlink(path, .ignore_missing = true);

    ASSERT_OK(unlinked);
}

static n00b_elf_rewrite_plan_t *
assert_insert_matches_plan(n00b_buffer_t *before, n00b_buffer_t *after)
{
    n00b_elf_binary_t *bin     = parse_elf_or_fail(before);
    n00b_buffer_t     *payload = chalk_mark_payload(after);
    n00b_elf_rewrite_metadata_request_t request =
        chalk_mark_request(payload);

    if (bin->overlay != nullptr) {
        request.policy.flags |=
            N00B_ELF_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY;
    }

    auto plan_result = n00b_elf_rewrite_plan_chalk_mark_insert(bin,
                                                               &request);
    ASSERT_OK(plan_result);
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);

    auto applied = n00b_elf_rewrite_apply_metadata_insert_plan(bin, plan);
    ASSERT_OK(applied);
    assert_buffer_eq(n00b_result_get(applied), after);

    return plan;
}

static n00b_elf_rewrite_plan_t *
assert_replace_matches_plan(n00b_buffer_t *before, n00b_buffer_t *after)
{
    n00b_elf_binary_t *bin     = parse_elf_or_fail(before);
    n00b_buffer_t     *payload = chalk_mark_payload(after);
    n00b_elf_rewrite_metadata_request_t request =
        chalk_mark_request(payload);

    auto plan_result = n00b_elf_rewrite_plan_chalk_mark_replace(bin,
                                                                &request);
    ASSERT_OK(plan_result);
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);

    auto applied = n00b_elf_rewrite_apply_chalk_mark_plan(bin, plan);
    ASSERT_OK(applied);
    assert_buffer_eq(n00b_result_get(applied), after);

    return plan;
}

static n00b_buffer_t *
finalized_mark_payload(n00b_buffer_t *hash_input)
{
    n00b_chalk_mark_t *mark = n00b_chalk_mark_new();
    n00b_buffer_t     *hash = n00b_chalk_sha256_buffer(hash_input);
    auto               fin  = n00b_chalk_mark_finalize(mark, hash);

    ASSERT_OK(fin);
    return n00b_result_get(fin);
}

static n00b_buffer_t *
surgically_marked_elf(n00b_buffer_t *base)
{
    n00b_elf_binary_t *bin     = parse_elf_or_fail(base);
    n00b_buffer_t     *payload = finalized_mark_payload(base);
    n00b_elf_rewrite_metadata_request_t request =
        chalk_mark_request(payload);

    auto plan_result = n00b_elf_rewrite_plan_chalk_mark_insert(bin,
                                                               &request);
    ASSERT_OK(plan_result);
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);

    auto applied = n00b_elf_rewrite_apply_metadata_insert_plan(bin, plan);
    ASSERT_OK(applied);
    n00b_buffer_t *marked = n00b_result_get(applied);

    N00B_TEST_REQUIRE(has_chalk_mark(marked));
    return marked;
}

static n00b_buffer_t *
surgically_marked_overlay_elf(void)
{
    n00b_buffer_t     *base    = supported_unmarked_overlay_elf();
    n00b_elf_binary_t *bin     = parse_elf_or_fail(base);
    n00b_buffer_t     *payload = finalized_mark_payload(base);
    n00b_elf_rewrite_metadata_request_t request =
        chalk_mark_overlay_fixture_request(payload);

    N00B_TEST_REQUIRE(bin->overlay != nullptr);

    auto plan_result = n00b_elf_rewrite_plan_chalk_mark_insert(bin,
                                                               &request);
    ASSERT_OK(plan_result);
    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);

    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED);

    auto applied = n00b_elf_rewrite_apply_metadata_insert_plan(bin, plan);
    ASSERT_OK(applied);
    n00b_buffer_t *marked = append_fixture_overlay(n00b_result_get(applied));

    n00b_elf_binary_t *marked_bin = parse_elf_or_fail(marked);
    N00B_TEST_REQUIRE(marked_bin->overlay != nullptr);
    N00B_TEST_REQUIRE(has_chalk_mark(marked));
    return marked;
}

static n00b_buffer_t *
malformed_non_elf(void)
{
    char raw[64];

    memset(raw, 0x31, sizeof(raw));
    return n00b_buffer_from_bytes(raw, sizeof(raw));
}

static void
make_profile_unsupported(n00b_buffer_t *buf)
{
    n00b_test_elf_put16((uint8_t *)buf->data + N00B_TEST_ELF_E_PHNUM, 0);
}

static void
test_insert_supported_uses_surgical_path_and_hash(void)
{
    n00b_buffer_t *base = supported_unmarked_elf();
    auto           hash = n00b_chalk_elf_hash_buffer(base);

    ASSERT_OK(hash);

    auto inserted = n00b_chalk_elf_insert_buffer(base,
                                                 n00b_chalk_mark_new());
    ASSERT_OK(inserted);
    n00b_chalk_io_result_t *io = n00b_result_get(inserted);

    N00B_TEST_REQUIRE(io->kind == N00B_CHALK_OUT_IN_BAND);
    N00B_TEST_REQUIRE(io->sidecar_suffix == nullptr);
    N00B_TEST_REQUIRE(chalk_mark_count(io->bytes) == 1);
    assert_extract_hash(io->bytes, n00b_result_get(hash));

    n00b_elf_rewrite_plan_t *plan =
        assert_insert_matches_plan(base, io->bytes);
    assert_unplanned_bytes_preserved(base, io->bytes, plan);
}

static void
test_insert_overlay_preserves_original_overlay_bytes(void)
{
    n00b_buffer_t     *base = supported_unmarked_overlay_elf();
    n00b_elf_binary_t *bin  = parse_elf_or_fail(base);

    N00B_TEST_REQUIRE(bin->overlay != nullptr);

    auto hash = n00b_chalk_elf_hash_buffer(base);
    ASSERT_OK(hash);

    auto inserted = n00b_chalk_elf_insert_buffer(base,
                                                 n00b_chalk_mark_new());
    ASSERT_OK(inserted);
    n00b_chalk_io_result_t *io = n00b_result_get(inserted);

    N00B_TEST_REQUIRE(io->kind == N00B_CHALK_OUT_IN_BAND);
    N00B_TEST_REQUIRE(chalk_mark_count(io->bytes) == 1);
    assert_extract_hash(io->bytes, n00b_result_get(hash));
    assert_overlay_bytes_preserved(base, io->bytes, bin);

    n00b_elf_rewrite_plan_t *plan =
        assert_insert_matches_plan(base, io->bytes);
    assert_unplanned_bytes_preserved(base, io->bytes, plan);
}

static void
test_remark_supported_replaces_live_mark_surgically(void)
{
    n00b_buffer_t *base = supported_unmarked_elf();
    auto           first = n00b_chalk_elf_insert_buffer(
        base,
        n00b_chalk_mark_new());

    ASSERT_OK(first);
    n00b_chalk_io_result_t *first_io = n00b_result_get(first);
    N00B_TEST_REQUIRE(chalk_mark_count(first_io->bytes) == 1);

    auto deleted = n00b_chalk_elf_delete_buffer(first_io->bytes);
    ASSERT_OK(deleted);
    n00b_chalk_io_result_t *deleted_io = n00b_result_get(deleted);
    N00B_TEST_REQUIRE(!has_chalk_mark(deleted_io->bytes));

    n00b_buffer_t *expected_hash = n00b_chalk_sha256_buffer(deleted_io->bytes);

    auto remarked = n00b_chalk_elf_insert_buffer(first_io->bytes,
                                                 n00b_chalk_mark_new());
    ASSERT_OK(remarked);
    n00b_chalk_io_result_t *remark_io = n00b_result_get(remarked);

    N00B_TEST_REQUIRE(remark_io->kind == N00B_CHALK_OUT_IN_BAND);
    N00B_TEST_REQUIRE(chalk_mark_count(remark_io->bytes) == 1);
    assert_extract_hash(remark_io->bytes, expected_hash);

    n00b_elf_rewrite_plan_t *plan =
        assert_replace_matches_plan(first_io->bytes, remark_io->bytes);
    assert_unplanned_bytes_preserved(first_io->bytes, remark_io->bytes, plan);
}

static void
test_hash_unmarked_supported_uses_original_bytes(void)
{
    n00b_buffer_t *bytes    = supported_unmarked_elf();
    n00b_buffer_t *expected = n00b_chalk_sha256_buffer(bytes);
    auto           hashed   = n00b_chalk_elf_hash_buffer(bytes);

    ASSERT_OK(hashed);
    assert_buffer_eq(n00b_result_get(hashed), expected);
}

static void
test_hash_marked_matches_surgical_delete_output(void)
{
    n00b_buffer_t *base   = supported_unmarked_elf();
    n00b_buffer_t *marked = surgically_marked_elf(base);

    auto hashed = n00b_chalk_elf_hash_buffer(marked);
    ASSERT_OK(hashed);

    auto deleted = n00b_chalk_elf_delete_buffer(marked);
    ASSERT_OK(deleted);
    n00b_chalk_io_result_t *io = n00b_result_get(deleted);

    N00B_TEST_REQUIRE(io->kind == N00B_CHALK_OUT_IN_BAND);
    N00B_TEST_REQUIRE(!has_chalk_mark(io->bytes));

    n00b_buffer_t *expected = n00b_chalk_sha256_buffer(io->bytes);
    assert_buffer_eq(n00b_result_get(hashed), expected);
}

static void
test_delete_removes_mark_and_extract_then_fails(void)
{
    n00b_buffer_t *base   = supported_unmarked_elf();
    n00b_buffer_t *marked = surgically_marked_elf(base);

    auto before_extract = n00b_chalk_elf_extract_buffer(marked);
    ASSERT_OK(before_extract);

    auto deleted = n00b_chalk_elf_delete_buffer(marked);
    ASSERT_OK(deleted);

    n00b_chalk_io_result_t *io = n00b_result_get(deleted);
    N00B_TEST_REQUIRE(io->kind == N00B_CHALK_OUT_IN_BAND);
    N00B_TEST_REQUIRE(!has_chalk_mark(io->bytes));

    auto after_extract = n00b_chalk_elf_extract_buffer(io->bytes);
    ASSERT_ERR(after_extract);
}

static void
test_delete_unmarked_supported_returns_original_bytes(void)
{
    n00b_buffer_t *bytes = supported_unmarked_elf();
    auto           del   = n00b_chalk_elf_delete_buffer(bytes);

    ASSERT_OK(del);
    n00b_chalk_io_result_t *io = n00b_result_get(del);

    N00B_TEST_REQUIRE(io->kind == N00B_CHALK_OUT_IN_BAND);
    assert_buffer_eq(io->bytes, bytes);
}

static void
test_unsupported_delete_fails_explicitly(void)
{
    n00b_buffer_t *bytes = supported_unmarked_elf();

    make_profile_unsupported(bytes);

    auto del = n00b_chalk_elf_delete_buffer(bytes);
    ASSERT_ERR(del);
}

static void
test_unsupported_insert_and_remark_fail_explicitly(void)
{
    n00b_buffer_t *bytes = supported_unmarked_elf();

    make_profile_unsupported(bytes);

    auto canonical = n00b_elf_build(parse_elf_or_fail(bytes));
    ASSERT_OK(canonical);
    N00B_TEST_REQUIRE(!buffer_eq(n00b_result_get(canonical), bytes));

    auto inserted = n00b_chalk_elf_insert_buffer(bytes,
                                                 n00b_chalk_mark_new());
    ASSERT_ERR(inserted);
    N00B_TEST_REQUIRE(n00b_result_get_err(inserted)
                      == N00B_ELF_REWRITE_ERR_TARGET_PROFILE);

    n00b_buffer_t *base = supported_unmarked_elf();
    auto           first = n00b_chalk_elf_insert_buffer(
        base,
        n00b_chalk_mark_new());
    ASSERT_OK(first);
    n00b_chalk_io_result_t *first_io = n00b_result_get(first);

    make_profile_unsupported(first_io->bytes);

    auto remarked = n00b_chalk_elf_insert_buffer(first_io->bytes,
                                                 n00b_chalk_mark_new());
    ASSERT_ERR(remarked);
    N00B_TEST_REQUIRE(n00b_result_get_err(remarked)
                      == N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
}

static void
test_parse_failure_raw_hash_fallback_only(void)
{
    n00b_buffer_t *bytes    = malformed_non_elf();
    n00b_buffer_t *expected = n00b_chalk_sha256_buffer(bytes);
    auto           hashed   = n00b_chalk_elf_hash_buffer(bytes);

    ASSERT_OK(hashed);
    assert_buffer_eq(n00b_result_get(hashed), expected);

    auto del = n00b_chalk_elf_delete_buffer(bytes);
    ASSERT_ERR(del);

    auto inserted = n00b_chalk_elf_insert_buffer(bytes,
                                                 n00b_chalk_mark_new());
    ASSERT_ERR(inserted);
    N00B_TEST_REQUIRE(n00b_result_get_err(inserted)
                      == N00B_ELF_REWRITE_ERR_TARGET_PROFILE);
}

static void
test_no_canonical_rebuild_fallback_for_required_unchalk(void)
{
    n00b_buffer_t *base   = supported_unmarked_elf();
    n00b_buffer_t *marked = surgically_marked_elf(base);

    make_profile_unsupported(marked);

    auto canonical = n00b_elf_build(parse_elf_or_fail(marked));
    ASSERT_OK(canonical);
    N00B_TEST_REQUIRE(!buffer_eq(n00b_result_get(canonical), marked));

    auto hashed = n00b_chalk_elf_hash_buffer(marked);
    ASSERT_ERR(hashed);

    auto del = n00b_chalk_elf_delete_buffer(marked);
    ASSERT_ERR(del);
}

static void
test_marked_overlay_public_paths_preserve_overlay_bytes(void)
{
    n00b_buffer_t     *marked = surgically_marked_overlay_elf();
    n00b_elf_binary_t *bin    = parse_elf_or_fail(marked);

    N00B_TEST_REQUIRE(bin->overlay != nullptr);
    N00B_TEST_REQUIRE(has_chalk_mark(marked));

    auto hashed = n00b_chalk_elf_hash_buffer(marked);
    ASSERT_OK(hashed);

    auto deleted = n00b_chalk_elf_delete_buffer(marked);
    ASSERT_OK(deleted);
    n00b_chalk_io_result_t *delete_io = n00b_result_get(deleted);

    N00B_TEST_REQUIRE(delete_io->kind == N00B_CHALK_OUT_IN_BAND);
    N00B_TEST_REQUIRE(!has_chalk_mark(delete_io->bytes));
    assert_overlay_bytes_preserved(marked, delete_io->bytes, bin);

    n00b_buffer_t *delete_hash = n00b_chalk_sha256_buffer(delete_io->bytes);
    assert_buffer_eq(n00b_result_get(hashed), delete_hash);

    auto remarked = n00b_chalk_elf_insert_buffer(marked,
                                                 n00b_chalk_mark_new());
    ASSERT_OK(remarked);
    n00b_chalk_io_result_t *remark_io = n00b_result_get(remarked);

    N00B_TEST_REQUIRE(remark_io->kind == N00B_CHALK_OUT_IN_BAND);
    N00B_TEST_REQUIRE(chalk_mark_count(remark_io->bytes) == 1);
    assert_extract_hash(remark_io->bytes, n00b_result_get(hashed));
    assert_overlay_bytes_preserved(marked, remark_io->bytes, bin);

    n00b_elf_rewrite_plan_t *plan =
        assert_replace_matches_plan(marked, remark_io->bytes);
    assert_unplanned_bytes_preserved(marked, remark_io->bytes, plan);
}

static void
test_delete_reinsert_hash_relationships(void)
{
    n00b_buffer_t *base = supported_unmarked_elf();
    auto           base_hash = n00b_chalk_elf_hash_buffer(base);

    ASSERT_OK(base_hash);

    auto first = n00b_chalk_elf_insert_buffer(base,
                                              n00b_chalk_mark_new());
    ASSERT_OK(first);
    n00b_chalk_io_result_t *first_io = n00b_result_get(first);
    assert_extract_hash(first_io->bytes, n00b_result_get(base_hash));

    auto first_deleted = n00b_chalk_elf_delete_buffer(first_io->bytes);
    ASSERT_OK(first_deleted);
    n00b_chalk_io_result_t *first_delete_io =
        n00b_result_get(first_deleted);
    N00B_TEST_REQUIRE(!has_chalk_mark(first_delete_io->bytes));

    auto first_hash = n00b_chalk_elf_hash_buffer(first_io->bytes);
    ASSERT_OK(first_hash);
    n00b_buffer_t *first_delete_hash =
        n00b_chalk_sha256_buffer(first_delete_io->bytes);
    assert_buffer_eq(n00b_result_get(first_hash), first_delete_hash);

    auto reinserted = n00b_chalk_elf_insert_buffer(first_delete_io->bytes,
                                                   n00b_chalk_mark_new());
    ASSERT_OK(reinserted);
    n00b_chalk_io_result_t *reinsert_io = n00b_result_get(reinserted);
    N00B_TEST_REQUIRE(chalk_mark_count(reinsert_io->bytes) == 1);
    assert_extract_hash(reinsert_io->bytes, first_delete_hash);

    auto reinsert_deleted = n00b_chalk_elf_delete_buffer(reinsert_io->bytes);
    ASSERT_OK(reinsert_deleted);
    n00b_chalk_io_result_t *reinsert_delete_io =
        n00b_result_get(reinsert_deleted);
    N00B_TEST_REQUIRE(!has_chalk_mark(reinsert_delete_io->bytes));

    auto reinsert_hash = n00b_chalk_elf_hash_buffer(reinsert_io->bytes);
    ASSERT_OK(reinsert_hash);
    n00b_buffer_t *reinsert_delete_hash =
        n00b_chalk_sha256_buffer(reinsert_delete_io->bytes);
    assert_buffer_eq(n00b_result_get(reinsert_hash), reinsert_delete_hash);

    auto remarked = n00b_chalk_elf_insert_buffer(reinsert_io->bytes,
                                                 n00b_chalk_mark_new());
    ASSERT_OK(remarked);
    n00b_chalk_io_result_t *remark_io = n00b_result_get(remarked);
    N00B_TEST_REQUIRE(chalk_mark_count(remark_io->bytes) == 1);
    assert_extract_hash(remark_io->bytes, reinsert_delete_hash);
}

static void
test_file_wrappers_roundtrip_supported_fixture(void)
{
    n00b_string_t *path = temp_elf_path();
    n00b_buffer_t *base = supported_unmarked_elf();
    auto           base_hash = n00b_chalk_elf_hash_buffer(base);

    ASSERT_OK(base_hash);
    unlink_file_or_fail(path);
    write_file_or_fail(path, base);

    auto file_hash = n00b_chalk_elf_hash_file(path);
    ASSERT_OK(file_hash);
    assert_buffer_eq(n00b_result_get(file_hash), n00b_result_get(base_hash));

    auto inserted = n00b_chalk_elf_insert_file(path,
                                               n00b_chalk_mark_new());
    ASSERT_OK(inserted);
    n00b_chalk_io_result_t *insert_io = n00b_result_get(inserted);
    N00B_TEST_REQUIRE(insert_io->kind == N00B_CHALK_OUT_IN_BAND);

    n00b_buffer_t *on_disk_inserted = read_file_or_fail(path);
    assert_buffer_eq(on_disk_inserted, insert_io->bytes);

    auto extracted = n00b_chalk_elf_extract_file(path);
    ASSERT_OK(extracted);
    assert_extract_result_hash(n00b_result_get(extracted),
                               n00b_result_get(base_hash));

    auto marked_file_hash = n00b_chalk_elf_hash_file(path);
    auto marked_buf_hash  = n00b_chalk_elf_hash_buffer(on_disk_inserted);
    ASSERT_OK(marked_file_hash);
    ASSERT_OK(marked_buf_hash);
    assert_buffer_eq(n00b_result_get(marked_file_hash),
                     n00b_result_get(marked_buf_hash));

    auto deleted = n00b_chalk_elf_delete_file(path);
    ASSERT_OK(deleted);
    n00b_chalk_io_result_t *delete_io = n00b_result_get(deleted);
    N00B_TEST_REQUIRE(delete_io->kind == N00B_CHALK_OUT_IN_BAND);
    N00B_TEST_REQUIRE(!has_chalk_mark(delete_io->bytes));

    n00b_buffer_t *on_disk_deleted = read_file_or_fail(path);
    assert_buffer_eq(on_disk_deleted, delete_io->bytes);

    auto extract_after_delete = n00b_chalk_elf_extract_file(path);
    ASSERT_ERR(extract_after_delete);

    auto deleted_file_hash = n00b_chalk_elf_hash_file(path);
    auto deleted_buf_hash  = n00b_chalk_elf_hash_buffer(on_disk_deleted);
    ASSERT_OK(deleted_file_hash);
    ASSERT_OK(deleted_buf_hash);
    assert_buffer_eq(n00b_result_get(deleted_file_hash),
                     n00b_result_get(deleted_buf_hash));

    unlink_file_or_fail(path);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime = {};

    n00b_init(&runtime, argc, argv);

    test_insert_supported_uses_surgical_path_and_hash();
    test_insert_overlay_preserves_original_overlay_bytes();
    test_remark_supported_replaces_live_mark_surgically();
    test_hash_unmarked_supported_uses_original_bytes();
    test_hash_marked_matches_surgical_delete_output();
    test_delete_removes_mark_and_extract_then_fails();
    test_delete_unmarked_supported_returns_original_bytes();
    test_unsupported_delete_fails_explicitly();
    test_unsupported_insert_and_remark_fail_explicitly();
    test_parse_failure_raw_hash_fallback_only();
    test_no_canonical_rebuild_fallback_for_required_unchalk();
    test_marked_overlay_public_paths_preserve_overlay_bytes();
    test_delete_reinsert_hash_relationships();
    test_file_wrappers_roundtrip_supported_fixture();

    return 0;
}
