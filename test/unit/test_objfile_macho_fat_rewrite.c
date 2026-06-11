#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/buffer.h"
#include "core/pool.h"
#include "core/mmaps.h"
#include "adt/list.h"
#include "adt/option.h"
#include "compiler/objfile/macho_build.h"
#include "compiler/objfile/macho_rewrite.h"
#include "compiler/objfile/macho_rewrite_admit.h"
#include "compiler/objfile/macho_fat_rewrite.h"
#include "internal/compiler/objfile/macho_fat_rewrite_internal.h"
#include "text/strings/string_ops.h"

// ============================================================================
// Fixture helpers
// ============================================================================

// Build a parsed 2-slice fat (arm64 + x86_64). The returned fat is the parsed
// container: it has populated binaries[] AND slices[] (D-020), and each
// binary's stream->buf is the whole fat file. *out_buf receives the fat bytes.
static n00b_macho_fat_t *
build_parsed_two_slice_fat(n00b_buffer_t **out_buf)
{
    n00b_macho_binary_t *arm64 = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);
    n00b_macho_segment_t *arm64_text = n00b_macho_add_segment(
        arm64, "__TEXT", 5, 5);
    arm64_text->vmaddr = 0x100000000ULL;

    n00b_macho_binary_t *x86 = n00b_macho_binary_new(
        CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, MH_EXECUTE);
    n00b_macho_segment_t *x86_text = n00b_macho_add_segment(
        x86, "__TEXT", 5, 5);
    x86_text->vmaddr = 0x100000000ULL;

    n00b_macho_fat_t *fat = n00b_alloc(n00b_macho_fat_t);
    fat->count           = 2;
    fat->binaries        = n00b_alloc_array(n00b_macho_binary_t *, 2);
    fat->binaries[0]     = arm64;
    fat->binaries[1]     = x86;

    auto r = n00b_macho_build_fat(fat);
    assert(n00b_result_is_ok(r));
    n00b_buffer_t *buf = n00b_result_get(r);
    assert(buf != nullptr);

    n00b_bstream_t *s  = n00b_bstream_new(buf);
    auto            r2 = n00b_macho_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_fat_t *parsed = n00b_result_get(r2);
    assert(parsed->count == 2);
    assert(parsed->slices != nullptr);

    if (out_buf != nullptr) {
        *out_buf = buf;
    }
    return parsed;
}

// Build a parsed arm64-only fat (count == 1) the same way.
static n00b_macho_fat_t *
build_parsed_arm64_only_fat(void)
{
    n00b_macho_binary_t *arm64 = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);
    n00b_macho_segment_t *arm64_text = n00b_macho_add_segment(
        arm64, "__TEXT", 5, 5);
    arm64_text->vmaddr = 0x100000000ULL;

    n00b_macho_fat_t *fat = n00b_alloc(n00b_macho_fat_t);
    fat->count       = 1;
    fat->binaries    = n00b_alloc_array(n00b_macho_binary_t *, 1);
    fat->binaries[0] = arm64;

    auto r = n00b_macho_build_fat(fat);
    assert(n00b_result_is_ok(r));

    n00b_bstream_t *s  = n00b_bstream_new(n00b_result_get(r));
    auto            r2 = n00b_macho_parse(s);
    assert(n00b_result_is_ok(r2));

    n00b_macho_fat_t *parsed = n00b_result_get(r2);
    assert(parsed->count == 1);
    return parsed;
}

// Find the plan whose index matches `idx`.
static n00b_macho_fat_rewrite_slice_plan_t *
plan_for_index(n00b_list_t(n00b_macho_fat_rewrite_slice_plan_t *) *plans,
               uint32_t idx)
{
    size_t n = n00b_list_len(*plans);
    for (size_t i = 0; i < n; i++) {
        n00b_macho_fat_rewrite_slice_plan_t *p = n00b_list_get(*plans, i);
        if (p->index == idx) {
            return p;
        }
    }
    return nullptr;
}

// ============================================================================
// P1-a: 2-slice fat → 1 REWRITE(arm64) + 1 PASSTHROUGH(x86_64) under ARM64_ONLY
// ============================================================================

static void
test_select_two_slice_arm64_only(void)
{
    n00b_macho_fat_t *fat = build_parsed_two_slice_fat(nullptr);

    n00b_macho_fat_rewrite_request_t req = {
        .policy = N00B_MACHO_FAT_SELECT_ARM64_ONLY,
    };

    auto r = n00b_macho_fat_select(fat, &req);
    assert(n00b_result_is_ok(r));

    n00b_list_t(n00b_macho_fat_rewrite_slice_plan_t *) *plans
        = n00b_result_get(r);
    assert((uint32_t)n00b_list_len(*plans) == 2);

    uint32_t rewrites = 0, passthroughs = 0;
    size_t   n = n00b_list_len(*plans);
    for (size_t i = 0; i < n; i++) {
        n00b_macho_fat_rewrite_slice_plan_t *p = n00b_list_get(*plans, i);
        if (p->disposition == N00B_MACHO_FAT_SLICE_REWRITE) {
            rewrites++;
            assert(p->cputype == (uint32_t)CPU_TYPE_ARM64);
        }
        else if (p->disposition == N00B_MACHO_FAT_SLICE_PASSTHROUGH) {
            passthroughs++;
            assert(p->cputype == (uint32_t)CPU_TYPE_X86_64);
        }
    }

    assert(rewrites == 1);
    assert(passthroughs == 1);

    printf("  [PASS] select_two_slice_arm64_only (P1-a)\n");
}

// ============================================================================
// P1-b: arm64-only fat → 1 REWRITE; EXPLICIT_INDEX out-of-range → NO_TARGET
// ============================================================================

static void
test_select_arm64_only_and_explicit_oob(void)
{
    n00b_macho_fat_t *fat = build_parsed_arm64_only_fat();

    // ARM64_ONLY on a count==1 arm64 fat → exactly one REWRITE.
    n00b_macho_fat_rewrite_request_t req = {
        .policy = N00B_MACHO_FAT_SELECT_ARM64_ONLY,
    };
    auto r = n00b_macho_fat_select(fat, &req);
    assert(n00b_result_is_ok(r));

    n00b_list_t(n00b_macho_fat_rewrite_slice_plan_t *) *plans
        = n00b_result_get(r);
    assert((uint32_t)n00b_list_len(*plans) == 1);

    n00b_macho_fat_rewrite_slice_plan_t *p0 = n00b_list_get(*plans, 0);
    assert(p0->disposition == N00B_MACHO_FAT_SLICE_REWRITE);
    assert(p0->cputype == (uint32_t)CPU_TYPE_ARM64);

    // EXPLICIT_INDEX out of range → Err(NO_TARGET_SLICE).
    n00b_macho_fat_rewrite_request_t req_oob = {
        .policy         = N00B_MACHO_FAT_SELECT_EXPLICIT_INDEX,
        .explicit_index = 7, // out of range for count==1
    };
    auto r_oob = n00b_macho_fat_select(fat, &req_oob);
    assert(n00b_result_is_err(r_oob));
    assert(n00b_result_get_err(r_oob) == N00B_MACHO_FAT_ERR_NO_TARGET_SLICE);

    printf("  [PASS] select_arm64_only_and_explicit_oob (P1-b)\n");
}

// ============================================================================
// P1-c: thin (non-fat) buffer wrapped count==1 → per-slice REWRITE emits valid
//        thin bytes that re-parse via parse_single (detached-buffer path D-034).
// ============================================================================

static void
test_per_slice_rewrite_thin_bytes_reparse(void)
{
    // Build a thin arm64 binary and wrap it as a count==1 fat with a manual
    // slice descriptor (offset 0, full size). The thin's stream is the thin
    // buffer itself, so the detached extract [0, +size) reproduces it.
    n00b_macho_binary_t *thin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);
    n00b_macho_segment_t *text = n00b_macho_add_segment(thin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    auto br = n00b_macho_build(thin);
    assert(n00b_result_is_ok(br));
    n00b_buffer_t *thin_buf = n00b_result_get(br);

    n00b_bstream_t *ts = n00b_bstream_new(thin_buf);
    auto            pr = n00b_macho_parse_single(ts);
    assert(n00b_result_is_ok(pr));
    n00b_macho_binary_t *parsed_thin = n00b_result_get(pr);
    assert(parsed_thin->fat_offset == 0);

    n00b_macho_fat_t *fat = n00b_alloc(n00b_macho_fat_t);
    fat->count           = 1;
    fat->binaries        = n00b_alloc_array(n00b_macho_binary_t *, 1);
    fat->binaries[0]     = parsed_thin;
    fat->slices          = n00b_alloc_array(n00b_macho_fat_slice_t, 1);
    fat->slices[0].cputype = (uint32_t)CPU_TYPE_ARM64;
    fat->slices[0].offset  = 0;
    fat->slices[0].size    = (uint64_t)thin_buf->byte_len;
    fat->slices[0].align   = 14;

    auto tr = _n00b_macho_fat_slice_thin_bytes(
        fat, 0, N00B_MACHO_FAT_SLICE_REWRITE, nullptr, nullptr);
    assert(n00b_result_is_ok(tr));

    n00b_buffer_t *out = n00b_result_get(tr);
    assert(out != nullptr);
    assert(out->byte_len > 0);

    // The emitted thin bytes must re-parse as a slice-relative thin object.
    n00b_bstream_t *os = n00b_bstream_new(out);
    auto            rr = n00b_macho_parse_single(os);
    assert(n00b_result_is_ok(rr));
    n00b_macho_binary_t *reparsed = n00b_result_get(rr);
    assert(reparsed->fat_offset == 0);
    assert(reparsed->header.cputype == (uint32_t)CPU_TYPE_ARM64);

    printf("  [PASS] per_slice_rewrite_thin_bytes_reparse (P1-c)\n");
}

// ============================================================================
// P1-d: x86_64 PASSTHROUGH slice → thin bytes byte-identical to input extent
//        [offset, offset+size).
// ============================================================================

static void
test_passthrough_byte_identical(void)
{
    n00b_buffer_t    *fat_buf = nullptr;
    n00b_macho_fat_t *fat     = build_parsed_two_slice_fat(&fat_buf);

    // Locate the x86_64 slice index.
    uint32_t x86_index = fat->count; // sentinel
    for (uint32_t i = 0; i < fat->count; i++) {
        if (fat->slices[i].cputype == (uint32_t)CPU_TYPE_X86_64) {
            x86_index = i;
            break;
        }
    }
    assert(x86_index < fat->count);

    auto tr = _n00b_macho_fat_slice_thin_bytes(
        fat, x86_index, N00B_MACHO_FAT_SLICE_PASSTHROUGH, nullptr, nullptr);
    assert(n00b_result_is_ok(tr));

    n00b_buffer_t *out = n00b_result_get(tr);
    assert(out != nullptr);

    uint64_t off = fat->slices[x86_index].offset;
    uint64_t sz  = fat->slices[x86_index].size;

    assert((uint64_t)out->byte_len == sz);
    // Byte-identical to the input slice extent in the source fat buffer.
    assert(off + sz <= (uint64_t)fat_buf->byte_len);
    assert(memcmp(out->data, fat_buf->data + off, (size_t)sz) == 0);

    printf("  [PASS] passthrough_byte_identical (P1-d)\n");
}

// ============================================================================
// P1-e: arm64 REWRITE slice + metadata carrier request — per-slice REWRITE
//        applies the carrier (WP-005 §3 path); output re-parses via parse_single,
//        carries the inserted note, and differs from the no-carrier bytes.
// ============================================================================

// Build a count==1 arm64 fat whose single slice covers a freshly-built thin
// arm64 object [0, +size). Mirrors P1-c's fixture (the thin stream is the thin
// buffer itself, so the detached extract reproduces it).
static n00b_macho_fat_t *
build_thin_wrapped_count1_fat(void)
{
    n00b_macho_binary_t *thin = n00b_macho_binary_new(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_EXECUTE);
    n00b_macho_segment_t *text = n00b_macho_add_segment(thin, "__TEXT", 5, 5);
    text->vmaddr = 0x100000000ULL;

    auto br = n00b_macho_build(thin);
    assert(n00b_result_is_ok(br));
    n00b_buffer_t *thin_buf = n00b_result_get(br);

    n00b_bstream_t *ts = n00b_bstream_new(thin_buf);
    auto            pr = n00b_macho_parse_single(ts);
    assert(n00b_result_is_ok(pr));
    n00b_macho_binary_t *parsed_thin = n00b_result_get(pr);
    assert(parsed_thin->fat_offset == 0);

    n00b_macho_fat_t *fat = n00b_alloc(n00b_macho_fat_t);
    fat->count             = 1;
    fat->binaries          = n00b_alloc_array(n00b_macho_binary_t *, 1);
    fat->binaries[0]       = parsed_thin;
    fat->slices            = n00b_alloc_array(n00b_macho_fat_slice_t, 1);
    fat->slices[0].cputype = (uint32_t)CPU_TYPE_ARM64;
    fat->slices[0].offset  = 0;
    fat->slices[0].size    = (uint64_t)thin_buf->byte_len;
    fat->slices[0].align   = 14;

    return fat;
}

static void
test_per_slice_rewrite_with_carrier(void)
{
    // No-carrier REWRITE output (the P1-c path) — the baseline to differ from.
    n00b_macho_fat_t *fat_nc = build_thin_wrapped_count1_fat();
    auto tr_nc = _n00b_macho_fat_slice_thin_bytes(
        fat_nc, 0, N00B_MACHO_FAT_SLICE_REWRITE, nullptr, nullptr);
    assert(n00b_result_is_ok(tr_nc));
    n00b_buffer_t *out_nc = n00b_result_get(tr_nc);
    assert(out_nc != nullptr);

    // Carrier-present REWRITE: a non-reserved metadata request (owner !=
    // reserved chalk/bundle owners), so the general metadata-insert path admits
    // it. Construction follows test_objfile_macho_rewrite.c:make_request.
    uint8_t payload_bytes[96];
    for (int i = 0; i < 96; i++) {
        payload_bytes[i] = 0xAB;
    }
    n00b_buffer_t *payload = n00b_buffer_from_bytes((char *)payload_bytes,
                                                    (int64_t)96);

    n00b_macho_rewrite_metadata_request_t carrier = {
        .note_owner            = r"wp007.fat",
        .note_name             = r"metadata",
        .payload               = payload,
        .file_alignment        = 0,
        .preferred_file_offset = n00b_option_none(uint64_t),
        .policy = (n00b_macho_rewrite_admit_policy_t){.flags = 0},
    };

    n00b_macho_fat_t *fat = build_thin_wrapped_count1_fat();
    auto tr = _n00b_macho_fat_slice_thin_bytes(
        fat, 0, N00B_MACHO_FAT_SLICE_REWRITE, &carrier, nullptr);
    assert(n00b_result_is_ok(tr));
    n00b_buffer_t *out = n00b_result_get(tr);
    assert(out != nullptr);
    assert(out->byte_len > 0);

    // The carrier output re-parses as a slice-relative thin arm64 object.
    n00b_bstream_t *os = n00b_bstream_new(out);
    auto            rr = n00b_macho_parse_single(os);
    assert(n00b_result_is_ok(rr));
    n00b_macho_binary_t *reparsed = n00b_result_get(rr);
    assert(reparsed->fat_offset == 0);
    assert(reparsed->header.cputype == (uint32_t)CPU_TYPE_ARM64);

    // The inserted carrier note is present: an LC_NOTE whose data_owner matches
    // the request note_owner. (data_owner is NUL-padded to 16 bytes.)
    bool found_note = false;
    for (uint32_t i = 0; i < reparsed->num_commands; i++) {
        n00b_macho_command_t *cmd = &reparsed->commands[i];
        if (cmd->cmd != LC_NOTE || cmd->raw_data == nullptr) {
            continue;
        }
        const char *owner = (const char *)cmd->raw_data->data + 8; // data_owner
        if (strncmp(owner, "wp007.fat", 16) == 0) {
            found_note = true;
            break;
        }
    }
    assert(found_note);

    // The carrier output differs from the no-carrier output (the note was
    // inserted): the carrier path is genuinely exercised (DoD item 3).
    bool differs = (out->byte_len != out_nc->byte_len)
                   || (memcmp(out->data,
                              out_nc->data,
                              (size_t)out->byte_len)
                       != 0);
    assert(differs);

    printf("  [PASS] per_slice_rewrite_with_carrier (P1-e)\n");
}

// ============================================================================
// P2-a: 2-slice fat, no carrier → refat output re-parses; count==2; cputypes
//        preserved; offsets 16K-aligned & strictly increasing.
// ============================================================================

// Produce the per-slice (thin bytes, cputype, cpusubtype, align) arrays for a
// parsed fat using detached passthrough for every slice (no rewrite). Returns
// the slice count via *out_count.
static void
collect_passthrough_slices(n00b_macho_fat_t *fat,
                           n00b_buffer_t  ***out_thin,
                           uint32_t        **out_cputypes,
                           uint32_t        **out_cpusubtypes,
                           uint32_t        **out_aligns,
                           uint32_t         *out_count)
{
    uint32_t        count       = fat->count;
    n00b_buffer_t **thin        = n00b_alloc_array(n00b_buffer_t *, count);
    uint32_t       *cputypes    = n00b_alloc_array(uint32_t, count);
    uint32_t       *cpusubtypes = n00b_alloc_array(uint32_t, count);
    uint32_t       *aligns      = n00b_alloc_array(uint32_t, count);

    for (uint32_t i = 0; i < count; i++) {
        auto tr = _n00b_macho_fat_slice_thin_bytes(
            fat, i, N00B_MACHO_FAT_SLICE_PASSTHROUGH, nullptr, nullptr);
        assert(n00b_result_is_ok(tr));
        thin[i]        = n00b_result_get(tr);
        cputypes[i]    = fat->slices[i].cputype;
        cpusubtypes[i] = fat->binaries[i]->header.cpusubtype;
        aligns[i]      = fat->slices[i].align;
    }

    *out_thin        = thin;
    *out_cputypes    = cputypes;
    *out_cpusubtypes = cpusubtypes;
    *out_aligns      = aligns;
    *out_count       = count;
}

static void
test_refat_two_slice_reparse(void)
{
    n00b_macho_fat_t *fat = build_parsed_two_slice_fat(nullptr);

    n00b_buffer_t **thin;
    uint32_t       *cputypes, *cpusubtypes, *aligns, count;
    collect_passthrough_slices(fat, &thin, &cputypes, &cpusubtypes, &aligns,
                               &count);
    assert(count == 2);

    auto rr = n00b_macho_refat(thin, cputypes, cpusubtypes, aligns, count);
    assert(n00b_result_is_ok(rr));
    n00b_buffer_t *fat_buf = n00b_result_get(rr);
    assert(fat_buf != nullptr);

    // The refat output re-parses with the same count and per-slice cputypes.
    n00b_bstream_t *s  = n00b_bstream_new(fat_buf);
    auto            pr = n00b_macho_parse(s);
    assert(n00b_result_is_ok(pr));
    n00b_macho_fat_t *parsed = n00b_result_get(pr);
    assert(parsed->count == 2);
    assert(parsed->slices != nullptr);

    uint64_t prev_end = 0;
    for (uint32_t i = 0; i < count; i++) {
        assert(parsed->slices[i].cputype == cputypes[i]);
        // 16K-aligned (align == 14 for both build_fat slices).
        assert((parsed->slices[i].offset & ((1u << 14) - 1)) == 0);
        // Strictly increasing offsets.
        assert(parsed->slices[i].offset >= prev_end);
        if (i > 0) {
            assert(parsed->slices[i].offset > parsed->slices[i - 1].offset);
        }
        prev_end = parsed->slices[i].offset + parsed->slices[i].size;
    }

    printf("  [PASS] refat_two_slice_reparse (P2-a)\n");
}

// ============================================================================
// P2-b: per-slice mixed align (arm64 align=14, x86_64 align=12) → each
//        fat_arch.offset == align_up(prev_end, 1<<align).
// ============================================================================

static void
test_refat_mixed_align(void)
{
    n00b_macho_fat_t *fat = build_parsed_two_slice_fat(nullptr);

    n00b_buffer_t **thin;
    uint32_t       *cputypes, *cpusubtypes, *aligns, count;
    collect_passthrough_slices(fat, &thin, &cputypes, &cpusubtypes, &aligns,
                               &count);
    assert(count == 2);

    // Assign mixed alignments per cputype (arm64 -> 14, x86_64 -> 12).
    for (uint32_t i = 0; i < count; i++) {
        aligns[i] = (cputypes[i] == (uint32_t)CPU_TYPE_ARM64) ? 14 : 12;
    }

    auto rr = n00b_macho_refat(thin, cputypes, cpusubtypes, aligns, count);
    assert(n00b_result_is_ok(rr));
    n00b_buffer_t *fat_buf = n00b_result_get(rr);

    n00b_bstream_t *s  = n00b_bstream_new(fat_buf);
    auto            pr = n00b_macho_parse(s);
    assert(n00b_result_is_ok(pr));
    n00b_macho_fat_t *parsed = n00b_result_get(pr);
    assert(parsed->count == count);

    // Recompute the expected placement: header padded to its first slice's
    // alignment, then each slice at align_up(prev_end, 1<<align).
    uint64_t hdr   = 8 + (uint64_t)count * 20;
    uint64_t cursor = hdr;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t a   = (uint64_t)1 << aligns[i];
        uint64_t off = (cursor + a - 1) & ~(a - 1);
        assert(parsed->slices[i].offset == off);
        assert((parsed->slices[i].offset & (a - 1)) == 0);
        cursor = off + parsed->slices[i].size;
    }

    printf("  [PASS] refat_mixed_align (P2-b)\n");
}

// ============================================================================
// P2-c: crafted oversize slice (padded offset > u32) → Err(SLICE_TOO_LARGE).
//        Achieved deterministically and cheaply by requesting align == 32 on a
//        later slice: align_up(cursor, 1<<32) == 4 GiB > UINT32_MAX, with no
//        large allocation (thin buffers stay tiny).
// ============================================================================

static void
test_refat_oversize_slice(void)
{
    n00b_macho_fat_t *fat = build_parsed_two_slice_fat(nullptr);

    n00b_buffer_t **thin;
    uint32_t       *cputypes, *cpusubtypes, *aligns, count;
    collect_passthrough_slices(fat, &thin, &cputypes, &cpusubtypes, &aligns,
                               &count);
    assert(count == 2);

    // Force the second slice's padded offset to 2^32 == 4 GiB, which exceeds the
    // u32 fat_arch.offset field. No multi-GB buffer is allocated — only the
    // alignment exponent is crafted.
    aligns[1] = 32;

    auto rr = n00b_macho_refat(thin, cputypes, cpusubtypes, aligns, count);
    assert(n00b_result_is_err(rr));
    assert(n00b_result_get_err(rr) == N00B_MACHO_FAT_ERR_SLICE_TOO_LARGE);

    printf("  [PASS] refat_oversize_slice (P2-c)\n");
}

// ============================================================================
// P2-d: 2-slice fat + metadata carrier (arm64) → fat_rewrite output re-parses;
//        arm64 slice has the carrier note; x86_64 slice byte-identical to input.
// ============================================================================

static void
test_fat_rewrite_with_carrier(void)
{
    n00b_buffer_t    *fat_buf = nullptr;
    n00b_macho_fat_t *fat     = build_parsed_two_slice_fat(&fat_buf);

    uint8_t payload_bytes[96];
    for (int i = 0; i < 96; i++) {
        payload_bytes[i] = 0xCD;
    }
    n00b_buffer_t *payload = n00b_buffer_from_bytes((char *)payload_bytes,
                                                    (int64_t)96);

    n00b_macho_rewrite_metadata_request_t carrier = {
        .note_owner            = r"wp007.fat",
        .note_name             = r"metadata",
        .payload               = payload,
        .file_alignment        = 0,
        .preferred_file_offset = n00b_option_none(uint64_t),
        .policy = (n00b_macho_rewrite_admit_policy_t){.flags = 0},
    };

    n00b_macho_fat_rewrite_request_t req = {
        .policy  = N00B_MACHO_FAT_SELECT_ARM64_ONLY,
        .carrier = &carrier,
    };

    auto fr = n00b_macho_fat_rewrite(fat, &req);
    assert(n00b_result_is_ok(fr));
    n00b_macho_fat_rewrite_result_t *res = n00b_result_get(fr);
    assert(res != nullptr);
    assert(res->slice_count == 2);
    assert(res->buffer != nullptr);

    // The output re-parses as a 2-slice fat.
    n00b_bstream_t *s  = n00b_bstream_new(res->buffer);
    auto            pr = n00b_macho_parse(s);
    assert(n00b_result_is_ok(pr));
    n00b_macho_fat_t *parsed = n00b_result_get(pr);
    assert(parsed->count == 2);

    // Locate the arm64 and x86_64 slices in the output.
    uint32_t arm_idx = parsed->count, x86_idx = parsed->count;
    for (uint32_t i = 0; i < parsed->count; i++) {
        if (parsed->slices[i].cputype == (uint32_t)CPU_TYPE_ARM64) {
            arm_idx = i;
        }
        else if (parsed->slices[i].cputype == (uint32_t)CPU_TYPE_X86_64) {
            x86_idx = i;
        }
    }
    assert(arm_idx < parsed->count);
    assert(x86_idx < parsed->count);

    // The arm64 slice carries the inserted carrier note.
    n00b_macho_binary_t *arm_bin = parsed->binaries[arm_idx];
    bool found_note = false;
    for (uint32_t i = 0; i < arm_bin->num_commands; i++) {
        n00b_macho_command_t *cmd = &arm_bin->commands[i];
        if (cmd->cmd != LC_NOTE || cmd->raw_data == nullptr) {
            continue;
        }
        const char *owner = (const char *)cmd->raw_data->data + 8;
        if (strncmp(owner, "wp007.fat", 16) == 0) {
            found_note = true;
            break;
        }
    }
    assert(found_note);

    // The x86_64 slice is byte-identical to the input slice extent.
    uint32_t in_x86_idx = fat->count;
    for (uint32_t i = 0; i < fat->count; i++) {
        if (fat->slices[i].cputype == (uint32_t)CPU_TYPE_X86_64) {
            in_x86_idx = i;
            break;
        }
    }
    assert(in_x86_idx < fat->count);

    uint64_t in_off  = fat->slices[in_x86_idx].offset;
    uint64_t in_sz   = fat->slices[in_x86_idx].size;
    uint64_t out_off = parsed->slices[x86_idx].offset;
    uint64_t out_sz  = parsed->slices[x86_idx].size;

    assert(out_sz == in_sz);
    assert(in_off + in_sz <= (uint64_t)fat_buf->byte_len);
    assert(out_off + out_sz <= (uint64_t)res->buffer->byte_len);
    assert(memcmp(res->buffer->data + out_off,
                  fat_buf->data + in_off,
                  (size_t)in_sz)
           == 0);

    printf("  [PASS] fat_rewrite_with_carrier (P2-d)\n");
}

// ============================================================================
// P2-e: no-carrier fat_rewrite vs build_fat round-trip → byte-identical.
// ============================================================================

static void
test_fat_rewrite_roundtrip_identity(void)
{
    n00b_buffer_t    *fat_buf = nullptr;
    n00b_macho_fat_t *fat     = build_parsed_two_slice_fat(&fat_buf);

    // No-carrier fat_rewrite: every slice is detached passthrough/rewrite with a
    // null carrier, so the output must reproduce the input fat byte-for-byte.
    n00b_macho_fat_rewrite_request_t req = {
        .policy  = N00B_MACHO_FAT_SELECT_ARM64_ONLY,
        .carrier = nullptr,
    };

    auto fr = n00b_macho_fat_rewrite(fat, &req);
    assert(n00b_result_is_ok(fr));
    n00b_macho_fat_rewrite_result_t *res = n00b_result_get(fr);
    assert(res != nullptr);
    assert(res->buffer != nullptr);

    // The build_fat round-trip input is the fixture's own fat bytes (fat_buf was
    // produced by build_fat). A no-carrier re-fat of the same slices, at the
    // same align == 14, must be byte-identical.
    assert((uint64_t)res->buffer->byte_len == (uint64_t)fat_buf->byte_len);
    assert(memcmp(res->buffer->data,
                  fat_buf->data,
                  (size_t)fat_buf->byte_len)
           == 0);

    printf("  [PASS] fat_rewrite_roundtrip_identity (P2-e)\n");
}

// ============================================================================
// P2-f: enum sweep — each *_str(value) non-fallback; *_str(0xffff) fallback.
// ============================================================================

static void
test_str_mappers_sweep(void)
{
    // Disposition: every defined value maps to a distinct, non-fallback name.
    n00b_macho_fat_slice_disposition_t disps[] = {
        N00B_MACHO_FAT_SLICE_REWRITE,
        N00B_MACHO_FAT_SLICE_PASSTHROUGH,
        N00B_MACHO_FAT_SLICE_REJECT,
    };
    n00b_string_t *disp_fallback
        = n00b_macho_fat_slice_disposition_str(
            (n00b_macho_fat_slice_disposition_t)0xffff);
    assert(disp_fallback != nullptr);
    for (size_t i = 0; i < sizeof(disps) / sizeof(disps[0]); i++) {
        n00b_string_t *s = n00b_macho_fat_slice_disposition_str(disps[i]);
        assert(s != nullptr);
        assert(!n00b_unicode_str_eq(s, disp_fallback));
    }

    // Policy.
    n00b_macho_fat_select_policy_t policies[] = {
        N00B_MACHO_FAT_SELECT_ARM64_ONLY,
        N00B_MACHO_FAT_SELECT_ALL_ARM,
        N00B_MACHO_FAT_SELECT_EXPLICIT_INDEX,
    };
    n00b_string_t *pol_fallback
        = n00b_macho_fat_select_policy_str(
            (n00b_macho_fat_select_policy_t)0xffff);
    assert(pol_fallback != nullptr);
    for (size_t i = 0; i < sizeof(policies) / sizeof(policies[0]); i++) {
        n00b_string_t *s = n00b_macho_fat_select_policy_str(policies[i]);
        assert(s != nullptr);
        assert(!n00b_unicode_str_eq(s, pol_fallback));
    }

    // Error codes (-43xx).
    n00b_err_t errs[] = {
        N00B_MACHO_FAT_ERR_NULL_INPUT,
        N00B_MACHO_FAT_ERR_NOT_FAT,
        N00B_MACHO_FAT_ERR_NO_TARGET_SLICE,
        N00B_MACHO_FAT_ERR_SLICE_REWRITE,
        N00B_MACHO_FAT_ERR_ALIGN_OVERFLOW,
        N00B_MACHO_FAT_ERR_SLICE_TOO_LARGE,
        N00B_MACHO_FAT_ERR_REFAT,
    };
    n00b_string_t *err_fallback = n00b_macho_fat_err_str((n00b_err_t)0xffff);
    assert(err_fallback != nullptr);
    for (size_t i = 0; i < sizeof(errs) / sizeof(errs[0]); i++) {
        n00b_string_t *s = n00b_macho_fat_err_str(errs[i]);
        assert(s != nullptr);
        assert(!n00b_unicode_str_eq(s, err_fallback));
    }

    printf("  [PASS] str_mappers_sweep (P2-f)\n");
}

// ============================================================================
// P2-g: NFR-04 — a NON-null .allocator is honored. n00b_macho_refat and
//        n00b_macho_fat_rewrite must return a buffer whose backing memory is
//        owned by the supplied allocator (not the runtime default), and the
//        output must still re-parse.
//
// Ownership is asserted with the cheap address->allocator predicate
// n00b_mem_get_allocator (mmaps.h): it resolves the registered allocator that
// owns a pointer. We point it at the returned buffer's backing store
// (buf->data) — the bytes the allocator argument is required to own per NFR-04.
// ============================================================================

static void
test_refat_allocator_owned(void)
{
    // A non-default allocator: a freshly-initialized pool. Its pages are
    // registered, so n00b_mem_get_allocator can resolve ownership of any
    // pointer it hands out.
    n00b_pool_t       pool = {};
    n00b_allocator_t *alloc
        = n00b_pool_init(&pool, .name = "test_refat_allocator_owned");
    assert(alloc != nullptr);

    n00b_macho_fat_t *fat = build_parsed_two_slice_fat(nullptr);

    n00b_buffer_t **thin;
    uint32_t       *cputypes, *cpusubtypes, *aligns, count;
    collect_passthrough_slices(fat, &thin, &cputypes, &cpusubtypes, &aligns,
                               &count);
    assert(count == 2);

    // --- n00b_macho_refat honors .allocator ---
    auto rr = n00b_macho_refat(thin, cputypes, cpusubtypes, aligns, count,
                               .allocator = alloc);
    assert(n00b_result_is_ok(rr));
    n00b_buffer_t *fat_buf = n00b_result_get(rr);
    assert(fat_buf != nullptr);

    // The returned buffer's backing store is owned by our pool.
    auto refat_owner = n00b_mem_get_allocator(fat_buf->data);
    assert(n00b_option_is_set(refat_owner));
    assert(n00b_option_get(refat_owner) == alloc);

    // ...and the allocator-owned output still re-parses as a fat container.
    n00b_bstream_t *s1 = n00b_bstream_new(fat_buf);
    auto            p1 = n00b_macho_parse(s1);
    assert(n00b_result_is_ok(p1));
    assert(n00b_result_get(p1)->count == 2);

    // --- n00b_macho_fat_rewrite honors .allocator on result->buffer ---
    n00b_macho_fat_rewrite_request_t req = {
        .policy  = N00B_MACHO_FAT_SELECT_ARM64_ONLY,
        .carrier = nullptr,
    };
    auto fr = n00b_macho_fat_rewrite(fat, &req, .allocator = alloc);
    assert(n00b_result_is_ok(fr));
    n00b_macho_fat_rewrite_result_t *res = n00b_result_get(fr);
    assert(res != nullptr);
    assert(res->buffer != nullptr);

    auto buf_owner = n00b_mem_get_allocator(res->buffer->data);
    assert(n00b_option_is_set(buf_owner));
    assert(n00b_option_get(buf_owner) == alloc);

    n00b_bstream_t *s2 = n00b_bstream_new(res->buffer);
    auto            p2 = n00b_macho_parse(s2);
    assert(n00b_result_is_ok(p2));
    assert(n00b_result_get(p2)->count == 2);

    printf("  [PASS] refat_allocator_owned (P2-g)\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running MachO fat-rewrite (WP-007 Phase 1+2) tests...\n");

    test_select_two_slice_arm64_only();          // P1-a
    test_select_arm64_only_and_explicit_oob();   // P1-b
    test_per_slice_rewrite_thin_bytes_reparse(); // P1-c
    test_passthrough_byte_identical();           // P1-d
    test_per_slice_rewrite_with_carrier();       // P1-e

    test_refat_two_slice_reparse();              // P2-a
    test_refat_mixed_align();                    // P2-b
    test_refat_oversize_slice();                 // P2-c
    test_fat_rewrite_with_carrier();             // P2-d
    test_fat_rewrite_roundtrip_identity();       // P2-e
    test_str_mappers_sweep();                    // P2-f
    test_refat_allocator_owned();                // P2-g

    printf("All MachO fat-rewrite tests passed.\n");
    return 0;
}
