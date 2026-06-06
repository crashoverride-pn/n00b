/* src/chalk/elf.c -- ELF codec (primary + fallback).
 *
 *  Chalk embeds the mark as a `.chalk.mark` section in the ELF image.
 *  Existing-ELF hash/delete/insert/re-mark paths use the surgical rewrite
 *  layer to produce deterministic unchalked byte views and metadata-only
 *  `.chalk.mark` rewrites where supported.
 *
 *  The fallback codec (codecFallbackElf in chalk) is preserved as a
 *  hex-offset scan that doesn't depend on the full parser; it stays
 *  in elf_fallback.c. */

#include "n00b.h"
#include "core/buffer.h"
#include "core/string.h"
#include "core/sha256.h"
#include "core/alloc.h"
#include "compiler/objfile/elf.h"
#include "compiler/objfile/elf_rewrite.h"
#include "compiler/objfile/elf_types.h"
#include "compiler/objfile/bstream.h"
#include "chalk/n00b_chalk.h"
#include "internal/chalk/mark_internal.h"
#include "internal/chalk/sidecar_internal.h"
#include "internal/chalk/file_io.h"
#include "util/assert.h"

#include <string.h>

#define CHALK_SECTION_NAME ".chalk.mark"

typedef enum {
    CHALK_ELF_VIEW_OK,
    CHALK_ELF_VIEW_PARSE_REFUSED,
    CHALK_ELF_VIEW_ERR,
} chalk_elf_view_status_t;

typedef struct chalk_elf_view_result {
    chalk_elf_view_status_t status;
    n00b_buffer_t          *bytes;
    int                     err;
} chalk_elf_view_result_t;

static n00b_elf_binary_t *
parse_elf(n00b_buffer_t *bytes)
{
    if (bytes == nullptr) return nullptr;
    n00b_bstream_t *bs = n00b_bstream_new(bytes);
    if (bs == nullptr) return nullptr;
    auto pr = n00b_elf_parse(bs);
    if (n00b_result_is_err(pr)) return nullptr;
    return n00b_result_get(pr);
}

static n00b_buffer_t *
sha256_buffer(n00b_buffer_t *in)
{
    n00b_sha256_digest_t w;
    n00b_sha256_hash(in->data, in->byte_len, w);
    uint8_t b[32];
    for (int i = 0; i < 8; i++) {
        uint32_t x   = w[i];
        b[i * 4]     = (uint8_t)((x >> 24) & 0xff);
        b[i * 4 + 1] = (uint8_t)((x >> 16) & 0xff);
        b[i * 4 + 2] = (uint8_t)((x >> 8) & 0xff);
        b[i * 4 + 3] = (uint8_t)(x & 0xff);
    }
    return n00b_buffer_from_bytes((char *)b, 32);
}

static bool
elf_has_chalk_mark(n00b_elf_binary_t *bin)
{
    return n00b_option_is_set(n00b_elf_section_by_name(bin,
                                                       CHALK_SECTION_NAME));
}

static bool
elf_target_profile_supported(n00b_elf_binary_t *bin)
{
    auto profile_result = n00b_elf_rewrite_target_profile(bin);
    if (n00b_result_is_err(profile_result)) {
        return false;
    }

    n00b_elf_rewrite_target_profile_t profile =
        n00b_result_get(profile_result);
    return profile.reason == N00B_ELF_REWRITE_PROFILE_OK;
}

static chalk_elf_view_result_t
chalk_elf_unchalked_view(n00b_buffer_t *bytes, bool require_supported_noop)
{
    if (bytes == nullptr) {
        return (chalk_elf_view_result_t){
            .status = CHALK_ELF_VIEW_ERR,
            .err    = N00B_ELF_REWRITE_ERR_NULL_BINARY,
        };
    }

    n00b_elf_binary_t *bin = parse_elf(bytes);
    if (bin == nullptr) {
        return (chalk_elf_view_result_t){
            .status = CHALK_ELF_VIEW_PARSE_REFUSED,
        };
    }

    if (!elf_has_chalk_mark(bin)) {
        if (require_supported_noop && !elf_target_profile_supported(bin)) {
            return (chalk_elf_view_result_t){
                .status = CHALK_ELF_VIEW_ERR,
                .err    = N00B_ELF_REWRITE_ERR_TARGET_PROFILE,
            };
        }

        return (chalk_elf_view_result_t){
            .status = CHALK_ELF_VIEW_OK,
            .bytes  = bytes,
        };
    }

    auto delete_result = n00b_elf_rewrite_apply_chalk_mark_delete(bin);
    if (n00b_result_is_err(delete_result)) {
        return (chalk_elf_view_result_t){
            .status = CHALK_ELF_VIEW_ERR,
            .err    = n00b_result_get_err(delete_result),
        };
    }

    return (chalk_elf_view_result_t){
        .status = CHALK_ELF_VIEW_OK,
        .bytes  = n00b_result_get(delete_result),
    };
}

static n00b_elf_rewrite_metadata_request_t
chalk_mark_rewrite_request(n00b_buffer_t *payload)
{
    return (n00b_elf_rewrite_metadata_request_t){
        .section_name   = r".chalk.mark",
        .payload        = payload,
        .file_alignment = 8,
        .section_type   = SHT_PROGBITS,
        .section_flags  = 0,
        .policy         = {
            .flags = N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION
                   | N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY
                   | N00B_ELF_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY,
        },
    };
}

n00b_result_t(n00b_buffer_t *)
n00b_chalk_elf_hash_buffer(n00b_buffer_t *bytes)
{
    auto unchalked = chalk_elf_unchalked_view(bytes, false);
    switch (unchalked.status) {
    case CHALK_ELF_VIEW_OK:
        return n00b_result_ok(n00b_buffer_t *, sha256_buffer(unchalked.bytes));
    case CHALK_ELF_VIEW_PARSE_REFUSED:
        // Fall back to raw sha256 if the parser refuses the input.
        return n00b_result_ok(n00b_buffer_t *, n00b_chalk_sha256_buffer(bytes));
    case CHALK_ELF_VIEW_ERR:
        return n00b_result_err(n00b_buffer_t *, unchalked.err);
    }

    n00b_unreachable();
}

n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_elf_insert_buffer(n00b_buffer_t *bytes, n00b_chalk_mark_t *mark)
{
    if (bytes == nullptr) {
        return n00b_result_err(n00b_chalk_io_result_t *,
                               N00B_ELF_REWRITE_ERR_NULL_BINARY);
    }
    if (mark == nullptr) {
        return n00b_result_err(n00b_chalk_io_result_t *,
                               N00B_ELF_REWRITE_ERR_NULL_REQUEST);
    }

    n00b_elf_binary_t *bin = parse_elf(bytes);
    if (bin == nullptr) {
        return n00b_result_err(n00b_chalk_io_result_t *,
                               N00B_ELF_REWRITE_ERR_TARGET_PROFILE);
    }

    bool has_mark = elf_has_chalk_mark(bin);
    auto unchalked = chalk_elf_unchalked_view(bytes, true);
    switch (unchalked.status) {
    case CHALK_ELF_VIEW_OK:
        break;
    case CHALK_ELF_VIEW_PARSE_REFUSED:
        return n00b_result_err(n00b_chalk_io_result_t *,
                               N00B_ELF_REWRITE_ERR_TARGET_PROFILE);
    case CHALK_ELF_VIEW_ERR:
        return n00b_result_err(n00b_chalk_io_result_t *, unchalked.err);
    }

    n00b_buffer_t *hash_buf = sha256_buffer(unchalked.bytes);

    auto fin = n00b_chalk_mark_finalize(mark, hash_buf);
    if (n00b_result_is_err(fin)) {
        return n00b_result_err(n00b_chalk_io_result_t *,
                               N00B_ELF_REWRITE_ERR_APPLY);
    }
    n00b_buffer_t *encoded = n00b_result_get(fin);
    n00b_elf_rewrite_metadata_request_t request =
        chalk_mark_rewrite_request(encoded);

    n00b_result_t(n00b_buffer_t *) rewritten;
    if (has_mark) {
        rewritten = n00b_elf_rewrite_apply_chalk_mark_replace(bin,
                                                              &request);
    }
    else {
        auto plan_result = n00b_elf_rewrite_plan_chalk_mark_insert(bin,
                                                                   &request);
        if (n00b_result_is_err(plan_result)) {
            return n00b_result_err(n00b_chalk_io_result_t *,
                                   n00b_result_get_err(plan_result));
        }

        n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
        if (plan->outcome != N00B_ELF_REWRITE_PLAN_ACCEPTED) {
            return n00b_result_err(n00b_chalk_io_result_t *,
                                   N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
        }

        rewritten = n00b_elf_rewrite_apply_metadata_insert_plan(bin, plan);
    }
    if (n00b_result_is_err(rewritten)) {
        return n00b_result_err(n00b_chalk_io_result_t *,
                               n00b_result_get_err(rewritten));
    }

    n00b_chalk_io_result_t *r = n00b_alloc(n00b_chalk_io_result_t);
    r->kind           = N00B_CHALK_OUT_IN_BAND;
    r->bytes          = n00b_result_get(rewritten);
    r->sidecar_suffix = nullptr;
    return n00b_result_ok(n00b_chalk_io_result_t *, r);
}

n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_elf_delete_buffer(n00b_buffer_t *bytes)
{
    auto unchalked = chalk_elf_unchalked_view(bytes, true);
    switch (unchalked.status) {
    case CHALK_ELF_VIEW_OK:
        break;
    case CHALK_ELF_VIEW_PARSE_REFUSED:
        return n00b_result_err(n00b_chalk_io_result_t *,
                               N00B_ELF_REWRITE_ERR_TARGET_PROFILE);
    case CHALK_ELF_VIEW_ERR:
        return n00b_result_err(n00b_chalk_io_result_t *, unchalked.err);
    }

    n00b_chalk_io_result_t *r = n00b_alloc(n00b_chalk_io_result_t);
    r->kind           = N00B_CHALK_OUT_IN_BAND;
    r->bytes          = unchalked.bytes;
    r->sidecar_suffix = nullptr;
    return n00b_result_ok(n00b_chalk_io_result_t *, r);
}

n00b_result_t(n00b_chalk_extract_result_t *)
n00b_chalk_elf_extract_buffer(n00b_buffer_t *bytes)
{
    if (bytes == nullptr) {
        return n00b_result_err(n00b_chalk_extract_result_t *,
                               N00B_ELF_REWRITE_ERR_NULL_BINARY);
    }
    n00b_elf_binary_t *bin = parse_elf(bytes);
    if (bin == nullptr) {
        return n00b_result_err(n00b_chalk_extract_result_t *,
                               N00B_ELF_REWRITE_ERR_TARGET_PROFILE);
    }
    n00b_option_t(n00b_elf_section_t *) sec_opt
        = n00b_elf_section_by_name(bin, CHALK_SECTION_NAME);
    if (!n00b_option_is_set(sec_opt)) {
        return n00b_result_err(n00b_chalk_extract_result_t *,
                               N00B_ELF_REWRITE_ERR_MARK_NOT_FOUND);
    }
    n00b_elf_section_t *sec = n00b_option_get(sec_opt);
    if (sec->content == nullptr) {
        return n00b_result_err(n00b_chalk_extract_result_t *,
                               N00B_ELF_REWRITE_ERR_MARK_NOT_FOUND);
    }
    // ELF section content is exact-size (no file-alignment padding
    // like PE), so we can hand the buffer straight to the parser.
    size_t mark_len = (size_t)sec->size;
    if (mark_len == 0 || mark_len > sec->content->byte_len) {
        mark_len = sec->content->byte_len;
    }
    n00b_buffer_t *trimmed = n00b_buffer_from_bytes(sec->content->data,
                                                     (int64_t)mark_len);
    return n00b_chalk_sidecar_parse_bytes(trimmed, N00B_CHALK_CODEC_ELF);
}

n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_elf_insert_file(n00b_string_t *path, n00b_chalk_mark_t *mark)
{
    return n00b_chalk_file_insert_via(path, mark, n00b_chalk_elf_insert_buffer);
}
n00b_result_t(n00b_chalk_io_result_t *)
n00b_chalk_elf_delete_file(n00b_string_t *path)
{
    return n00b_chalk_file_delete_via(path, n00b_chalk_elf_delete_buffer);
}
n00b_result_t(n00b_chalk_extract_result_t *)
n00b_chalk_elf_extract_file(n00b_string_t *path)
{
    return n00b_chalk_file_extract_via(path, n00b_chalk_elf_extract_buffer);
}
n00b_result_t(n00b_buffer_t *)
n00b_chalk_elf_hash_file(n00b_string_t *path)
{
    return n00b_chalk_file_hash_via(path, n00b_chalk_elf_hash_buffer);
}
