#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "n00b.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "adt/option.h"
#include "adt/result.h"
#include "compiler/objfile/bstream.h"
#include "compiler/objfile/elf.h"
#include "compiler/objfile/elf_layout.h"
#include "compiler/objfile/elf_rewrite_admit.h"
#include "compiler/objfile/elf_rewrite.h"
#include "text/strings/string_ops.h"
#include "util/assert.h"

#include "objfile_elf_casegen.h"

#define N00B_TEST_REQUIRE(expr) n00b_require((expr), #expr)

static bool
parse_succeeds(n00b_buffer_t *buf, n00b_elf_binary_t **out)
{
    n00b_bstream_t *stream = n00b_bstream_new(buf);
    auto            result = n00b_elf_parse(stream);

    if (n00b_result_is_err(result)) {
        if (out != nullptr) {
            *out = nullptr;
        }
        return false;
    }

    if (out != nullptr) {
        *out = n00b_result_get(result);
    }
    return true;
}

static n00b_buffer_t *
payload_new(uint8_t fill, size_t len)
{
    n00b_buffer_t *payload = n00b_buffer_new((int64_t)len);

    memset(payload->data, fill, len);
    payload->byte_len = len;
    return payload;
}

static n00b_elf_section_t *
require_section_named(n00b_elf_binary_t *bin, n00b_string_t *name)
{
    for (uint32_t i = 0; i < bin->num_sections; i++) {
        if (bin->sections[i].name != nullptr
            && n00b_unicode_str_eq(bin->sections[i].name, name)) {
            return &bin->sections[i];
        }
    }

    N00B_TEST_REQUIRE(false);
    return nullptr;
}

static void
assert_inserted_section(n00b_elf_binary_t *bin,
                        n00b_elf_rewrite_plan_t *plan,
                        n00b_elf_rewrite_metadata_request_t *request)
{
    n00b_elf_section_t *sec = require_section_named(bin, request->section_name);
    uint64_t expected_align = request->file_alignment == 0
                            ? 1
                            : request->file_alignment;

    N00B_TEST_REQUIRE(bin->header.shnum == plan->new_section_count);
    N00B_TEST_REQUIRE(sec == &bin->sections[bin->header.shnum - 1]);
    N00B_TEST_REQUIRE(sec->type == request->section_type);
    N00B_TEST_REQUIRE(sec->flags == request->section_flags);
    N00B_TEST_REQUIRE(sec->offset == plan->payload_offset);
    N00B_TEST_REQUIRE(sec->size == request->payload->byte_len);
    N00B_TEST_REQUIRE(sec->addralign == expected_align);
    N00B_TEST_REQUIRE(sec->content != nullptr);
    N00B_TEST_REQUIRE(sec->content->byte_len == request->payload->byte_len);
    N00B_TEST_REQUIRE(memcmp(sec->content->data,
                             request->payload->data,
                             request->payload->byte_len) == 0);
}

static void
check_known_case(const n00b_test_elf_case_t *test_case)
{
    n00b_buffer_t *buf = n00b_test_elf_case_generate(test_case);
    assert(buf != nullptr);

    n00b_elf_binary_t *bin = nullptr;
    bool               ok  = parse_succeeds(buf, &bin);

    switch (test_case->expect_parse) {
    case N00B_TEST_ELF_PARSE_OK:
        assert(ok);
        assert(bin != nullptr);
        break;
    case N00B_TEST_ELF_PARSE_REJECT:
        assert(!ok);
        assert(bin == nullptr);
        break;
    }

    printf("  [PASS] %s (%s)\n",
           test_case->name,
           test_case->expect_reason);
}

static void
test_divergence_classification_metadata(void)
{
    bool saw_n00b_broader    = false;
    bool saw_shared_scope    = false;
    bool saw_diagnostic_only = false;

    for (size_t i = 0; i < n00b_test_elf_case_count; i++) {
        const n00b_test_elf_case_t *test_case = &n00b_test_elf_cases[i];
        const char *classification =
            n00b_test_elf_divergence_name(test_case->divergence);

        assert(classification != nullptr);
        assert(classification[0] != '\0');

        switch (test_case->divergence) {
        case N00B_TEST_ELF_DIVERGENCE_SHARED_SCOPE:
            saw_shared_scope = true;
            break;
        case N00B_TEST_ELF_DIVERGENCE_N00B_BROADER:
            saw_n00b_broader = true;
            break;
        case N00B_TEST_ELF_DIVERGENCE_BRANDON_NARROWER:
            break;
        case N00B_TEST_ELF_DIVERGENCE_DIAGNOSTIC_ONLY:
            saw_diagnostic_only = true;
            break;
        }
    }

    assert(saw_shared_scope);
    assert(saw_n00b_broader);
    assert(saw_diagnostic_only);
    printf("  [PASS] divergence classification metadata\n");
}

static n00b_elf_layout_t *
layout_for_case(const char *name)
{
    const n00b_test_elf_case_t *test_case = n00b_test_elf_case_by_name(name);
    assert(test_case != nullptr);

    n00b_buffer_t *buf = n00b_test_elf_case_generate(test_case);
    assert(buf != nullptr);

    n00b_elf_binary_t *bin = nullptr;
    assert(parse_succeeds(buf, &bin));
    assert(bin != nullptr);

    auto layout = n00b_elf_layout_build(bin);
    assert(n00b_result_is_ok(layout));
    return n00b_result_get(layout);
}

static size_t
count_file_kind(n00b_elf_layout_t              *layout,
                uint64_t                        start,
                uint64_t                        end,
                n00b_elf_layout_interval_kind_t kind)
{
    auto overlaps = n00b_elf_layout_file_overlaps(layout, start, end);
    assert(n00b_result_is_ok(overlaps));
    n00b_elf_layout_interval_list_t list = n00b_result_get(overlaps);

    size_t count = 0;
    for (uint64_t i = 0; i < list.count; i++) {
        if (list.items[i].kind == kind) {
            count++;
        }
    }

    return count;
}

static size_t
count_vaddr_kind(n00b_elf_layout_t              *layout,
                 uint64_t                        start,
                 uint64_t                        end,
                 n00b_elf_layout_interval_kind_t kind)
{
    auto overlaps = n00b_elf_layout_vaddr_overlaps(layout, start, end);
    assert(n00b_result_is_ok(overlaps));
    n00b_elf_layout_interval_list_t list = n00b_result_get(overlaps);

    size_t count = 0;
    for (uint64_t i = 0; i < list.count; i++) {
        if (list.items[i].kind == kind) {
            count++;
        }
    }

    return count;
}

static bool
offset_is_planned_loadable_change(n00b_elf_rewrite_loadable_plan_t *plan,
                                  uint64_t                          offset)
{
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        if (offset >= plan->patches.data[i].file_offset
            && offset < plan->patches.data[i].file_end) {
            return true;
        }
    }

    return false;
}

static void
assert_unplanned_original_loadable_bytes_preserved(
    n00b_buffer_t *before,
    n00b_buffer_t *after,
    n00b_elf_rewrite_loadable_plan_t *plan)
{
    N00B_TEST_REQUIRE(after->byte_len >= before->byte_len);

    for (uint64_t i = 0; i < before->byte_len; i++) {
        if (offset_is_planned_loadable_change(plan, i)) {
            continue;
        }

        N00B_TEST_REQUIRE(before->data[i] == after->data[i]);
    }
}

static void
assert_loadable_padding_zeroed(n00b_buffer_t *out,
                               n00b_elf_rewrite_loadable_plan_t *plan)
{
    for (uint64_t i = 0; i < plan->patches.len; i++) {
        n00b_elf_rewrite_patch_t *patch = &plan->patches.data[i];

        if (patch->kind != N00B_ELF_REWRITE_PATCH_LOADABLE_PADDING) {
            continue;
        }

        N00B_TEST_REQUIRE(patch->file_offset <= patch->file_end);
        N00B_TEST_REQUIRE(patch->file_end <= out->byte_len);
        for (uint64_t j = patch->file_offset; j < patch->file_end; j++) {
            N00B_TEST_REQUIRE(out->data[j] == 0);
        }
    }
}

static void
assert_rewritten_loadable_payload(n00b_buffer_t *out,
                                  n00b_elf_rewrite_loadable_plan_t *plan,
                                  n00b_buffer_t *payload)
{
    N00B_TEST_REQUIRE(plan->payload_placement.kind
                      == N00B_ELF_REWRITE_LOADABLE_PLACEMENT_LOADABLE_PAYLOAD);
    N00B_TEST_REQUIRE(plan->payload_placement.file_end
                      == plan->payload_placement.file_offset
                       + payload->byte_len);
    N00B_TEST_REQUIRE(plan->payload_placement.file_end <= out->byte_len);
    N00B_TEST_REQUIRE(memcmp(out->data + plan->payload_placement.file_offset,
                             payload->data,
                             payload->byte_len) == 0);
}

static void
assert_rewritten_new_pt_load(n00b_elf_binary_t *rewritten,
                             n00b_elf_rewrite_loadable_plan_t *plan,
                             uint64_t offset,
                             uint64_t vaddr,
                             uint64_t paddr,
                             uint64_t filesz,
                             uint64_t memsz,
                             uint64_t align)
{
    N00B_TEST_REQUIRE(rewritten->num_segments == plan->new_segment_count);
    N00B_TEST_REQUIRE(plan->new_segment_count
                      == plan->original_segment_count + 1);

    n00b_elf_segment_t *seg =
        &rewritten->segments[plan->original_segment_count];
    N00B_TEST_REQUIRE(seg->type == PT_LOAD);
    N00B_TEST_REQUIRE(seg->flags == plan->segment_flags);
    N00B_TEST_REQUIRE(seg->offset == offset);
    N00B_TEST_REQUIRE(seg->vaddr == vaddr);
    N00B_TEST_REQUIRE(seg->paddr == paddr);
    N00B_TEST_REQUIRE(seg->filesz == filesz);
    N00B_TEST_REQUIRE(seg->memsz == memsz);
    N00B_TEST_REQUIRE(seg->align == align);
}

static n00b_elf_layout_gap_t
require_file_gap(n00b_elf_layout_t *layout,
                 uint64_t           start,
                 uint64_t           end,
                 uint64_t           min_size,
                 uint64_t           alignment)
{
    auto gap = n00b_elf_layout_find_file_gap(layout,
                                             start,
                                             end,
                                             min_size,
                                             alignment);
    assert(n00b_result_is_ok(gap));
    n00b_option_t(n00b_elf_layout_gap_t) gap_opt = n00b_result_get(gap);
    assert(n00b_option_is_set(gap_opt));
    return n00b_option_get(gap_opt);
}

static n00b_elf_rewrite_admit_metadata_request_t
admission_request_make(n00b_test_elf_admission_request_t request)
{
    n00b_elf_rewrite_admit_metadata_request_t admission = {
        .section_name    = r".n00b.test",
        .payload_size    = 16,
        .file_alignment  = 8,
        .section_type    = SHT_PROGBITS,
        .section_flags   = 0,
        .policy          = {
            .flags = N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY,
        },
    };

    switch (request) {
    case N00B_TEST_ELF_ADMISSION_STRICT_EOF:
        admission.policy.flags |=
            N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION;
        break;
    case N00B_TEST_ELF_ADMISSION_RELAXED_PREFERRED_GAP:
        admission.preferred_file_offset = n00b_option_set(uint64_t, 288);
        admission.file_alignment        = 16;
        break;
    case N00B_TEST_ELF_ADMISSION_RELAXED_OVERLAY_APPEND:
        admission.policy.flags |=
            N00B_ELF_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY;
        break;
    case N00B_TEST_ELF_ADMISSION_NONE:
    case N00B_TEST_ELF_ADMISSION_RELAXED_EOF:
    case N00B_TEST_ELF_ADMISSION_RELAXED_OVERLAY_PRESERVE:
        break;
    }

    return admission;
}

static n00b_elf_rewrite_metadata_request_t
rewrite_request_make(n00b_test_elf_rewrite_request_t request)
{
    n00b_elf_rewrite_metadata_request_t rewrite = {
        .section_name   = r".n00b.test",
        .payload        = payload_new(0x42, 16),
        .file_alignment = 8,
        .section_type   = SHT_PROGBITS,
        .section_flags  = 0,
        .policy         = {
            .flags = N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY,
        },
    };

    switch (request) {
    case N00B_TEST_ELF_REWRITE_RELAXED_PREFERRED_GAP:
        rewrite.preferred_file_offset = n00b_option_set(uint64_t, 288);
        rewrite.file_alignment        = 16;
        break;
    case N00B_TEST_ELF_REWRITE_RELAXED_OVERLAY_APPEND:
        rewrite.policy.flags |= N00B_ELF_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY;
        break;
    case N00B_TEST_ELF_REWRITE_RESERVED_REQUESTED_NAME:
        rewrite.section_name = r".chalk.mark";
        break;
    case N00B_TEST_ELF_REWRITE_NONE:
    case N00B_TEST_ELF_REWRITE_RELAXED_EOF:
    case N00B_TEST_ELF_REWRITE_RELAXED_OVERLAY_PRESERVE:
        break;
    }

    return rewrite;
}

static n00b_elf_rewrite_loadable_request_t
loadable_request_make(n00b_test_elf_loadable_request_t request)
{
    n00b_elf_rewrite_loadable_request_t loadable = {
        .payload          = payload_new(0x90, 32),
        .segment_flags    = PF_R | PF_X,
        .file_alignment   = 8,
        .vaddr_alignment  = 0x1000,
        .p_memsz          = 32,
        .phtab_strategy   = N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_DEFERRED,
        .policy           = {
            .flags = N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION
                   | N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY,
        },
    };

    switch (request) {
    case N00B_TEST_ELF_LOADABLE_IN_PLACE:
        loadable.phtab_strategy =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST;
        break;
    case N00B_TEST_ELF_LOADABLE_RELOCATE:
        loadable.phtab_strategy =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE;
        break;
    case N00B_TEST_ELF_LOADABLE_NONE:
    case N00B_TEST_ELF_LOADABLE_DEFERRED:
        break;
    }

    return loadable;
}

static void
check_admission_case(const n00b_test_elf_case_t *test_case,
                     bool                       *saw_phtab_outside_load,
                     bool                       *saw_entry_outside_load,
                     bool                       *saw_entry_memory_only,
                     bool                       *saw_pt_phdr_inconsistent,
                     bool                       *saw_overlay_policy,
                     bool                       *saw_nonzero_gap,
                     bool                       *saw_accepted_placement)
{
    n00b_buffer_t *buf = n00b_test_elf_case_generate(test_case);
    N00B_TEST_REQUIRE(buf != nullptr);

    n00b_elf_binary_t *bin = nullptr;
    N00B_TEST_REQUIRE(parse_succeeds(buf, &bin));
    N00B_TEST_REQUIRE(bin != nullptr);

    n00b_elf_rewrite_admit_metadata_request_t request =
        admission_request_make(test_case->admission_request);
    auto result = n00b_elf_rewrite_admit_metadata_insert(bin, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(result));

    n00b_elf_rewrite_admit_result_t admit = n00b_result_get(result);
    N00B_TEST_REQUIRE(admit.outcome == test_case->admission_outcome);
    N00B_TEST_REQUIRE(admit.rejection_reason == test_case->admission_reason);

    n00b_elf_rewrite_admit_placement_kind_t placement_kind =
        N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE;
    if (n00b_option_is_set(admit.placement)) {
        n00b_elf_rewrite_admit_placement_t placement =
            n00b_option_get(admit.placement);
        placement_kind = placement.kind;
    }

    N00B_TEST_REQUIRE(placement_kind == test_case->admission_placement);

    switch (test_case->admission_reason) {
    case N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_OUTSIDE_LOAD:
        *saw_phtab_outside_load = true;
        break;
    case N00B_ELF_REWRITE_ADMIT_REJECT_ENTRY_OUTSIDE_LOAD:
        *saw_entry_outside_load = true;
        break;
    case N00B_ELF_REWRITE_ADMIT_REJECT_ENTRY_MEMORY_ONLY:
        *saw_entry_memory_only = true;
        break;
    case N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_INCONSISTENT:
        *saw_pt_phdr_inconsistent = true;
        break;
    case N00B_ELF_REWRITE_ADMIT_REJECT_OVERLAY_POLICY:
        *saw_overlay_policy = true;
        break;
    case N00B_ELF_REWRITE_ADMIT_REJECT_UNKNOWN_NONZERO_BYTES:
        *saw_nonzero_gap = true;
        break;
    case N00B_ELF_REWRITE_ADMIT_REJECT_NONE:
        N00B_TEST_REQUIRE(
            admit.outcome == N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED);
        N00B_TEST_REQUIRE(test_case->admission_placement
                          != N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE);
        *saw_accepted_placement = true;
        break;
    default:
        break;
    }
}

static void
test_layout_known_answers(void)
{
    n00b_elf_layout_t *layout = layout_for_case("phtab_not_in_load");
    assert(count_file_kind(layout,
                           64,
                           120,
                           N00B_ELF_LAYOUT_INTERVAL_PHTAB) == 1);
    assert(count_file_kind(layout,
                           64,
                           120,
                           N00B_ELF_LAYOUT_INTERVAL_SEGMENT_FILE) == 0);

    layout = layout_for_case("entry_in_mem_not_file");
    assert(count_file_kind(layout,
                           0x101,
                           0x102,
                           N00B_ELF_LAYOUT_INTERVAL_SEGMENT_FILE) == 0);
    assert(count_vaddr_kind(layout,
                            0x400101,
                            0x400102,
                            N00B_ELF_LAYOUT_INTERVAL_SEGMENT_MEMORY) == 1);

    layout = layout_for_case("pt_phdr_bad_size");
    assert(count_file_kind(layout,
                           64,
                           176,
                           N00B_ELF_LAYOUT_INTERVAL_PHTAB) == 1);

    layout = layout_for_case("overlay_after_segments");
    assert(count_file_kind(layout,
                           512,
                           528,
                           N00B_ELF_LAYOUT_INTERVAL_OVERLAY) == 1);
    n00b_elf_layout_gap_t gap = require_file_gap(layout, 512, 528, 8, 1);
    assert(gap.kind == N00B_ELF_LAYOUT_GAP_OVERLAY);

    layout = layout_for_case("layout_nonzero_unknown");
    gap    = require_file_gap(layout, 288, 320, 4, 16);
    assert(gap.kind == N00B_ELF_LAYOUT_GAP_UNKNOWN_NONZERO);

    layout = layout_for_case("layout_classification");
    assert(count_vaddr_kind(layout,
                            0x400600,
                            0x400620,
                            N00B_ELF_LAYOUT_INTERVAL_SECTION_NOBITS_MEMORY) == 1);
    assert(count_file_kind(layout,
                           576,
                           608,
                           N00B_ELF_LAYOUT_INTERVAL_SECTION_NOBITS_MEMORY) == 0);

    printf("  [PASS] layout known-answer probes\n");
}

static void
test_admission_known_answers(void)
{
    bool saw_phtab_outside_load = false;
    bool saw_entry_outside_load = false;
    bool saw_entry_memory_only = false;
    bool saw_pt_phdr_inconsistent = false;
    bool saw_overlay_policy = false;
    bool saw_nonzero_gap = false;
    bool saw_accepted_placement = false;
    size_t count = 0;

    for (size_t i = 0; i < n00b_test_elf_case_count; i++) {
        const n00b_test_elf_case_t *test_case = &n00b_test_elf_cases[i];

        if (!n00b_test_elf_case_has_admission(test_case)) {
            continue;
        }

        N00B_TEST_REQUIRE(test_case->expect_parse == N00B_TEST_ELF_PARSE_OK);
        check_admission_case(test_case,
                             &saw_phtab_outside_load,
                             &saw_entry_outside_load,
                             &saw_entry_memory_only,
                             &saw_pt_phdr_inconsistent,
                             &saw_overlay_policy,
                             &saw_nonzero_gap,
                             &saw_accepted_placement);
        count++;
    }

    N00B_TEST_REQUIRE(count > 0);
    N00B_TEST_REQUIRE(saw_phtab_outside_load);
    N00B_TEST_REQUIRE(saw_entry_outside_load);
    N00B_TEST_REQUIRE(saw_entry_memory_only);
    N00B_TEST_REQUIRE(saw_pt_phdr_inconsistent);
    N00B_TEST_REQUIRE(saw_overlay_policy);
    N00B_TEST_REQUIRE(saw_nonzero_gap);
    N00B_TEST_REQUIRE(saw_accepted_placement);
}

static n00b_elf_rewrite_admit_placement_kind_t
rewrite_plan_placement_kind(n00b_elf_rewrite_plan_t *plan)
{
    if (!n00b_option_is_set(plan->admission.placement)) {
        return N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE;
    }

    n00b_elf_rewrite_admit_placement_t placement =
        n00b_option_get(plan->admission.placement);
    return placement.kind;
}

static void
mirror_target_mutation_to_header(n00b_elf_binary_t *bin,
                                 n00b_test_elf_target_mutation_t mutation,
                                 size_t file_size)
{
    switch (mutation) {
    case N00B_TEST_ELF_TARGET_MUTATION_INVALID_EHSIZE:
        bin->header.ehsize = 65;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_INVALID_SHENTSIZE:
        bin->header.shentsize = 65;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_INVALID_PHENTSIZE:
        bin->header.phentsize = 57;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHNUM_ZERO:
        bin->header.shnum = 0;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHNUM_ONE:
        bin->header.shnum = 1;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHNUM_LORESERVE:
        bin->header.shnum = N00B_TEST_ELF_SHN_LORESERVE;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHNUM_XINDEX:
        bin->header.shnum = SHN_XINDEX;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHOFF_ZERO:
        bin->header.shoff = 0;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHOFF_OUT_OF_BOUNDS:
        bin->header.shoff = file_size;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHOFF_WRAP:
        bin->header.shoff = UINT64_MAX - 32;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_ZERO:
        bin->header.shstrndx = 0;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_LORESERVE:
        bin->header.shstrndx = N00B_TEST_ELF_SHN_LORESERVE;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_XINDEX:
        bin->header.shstrndx = SHN_XINDEX;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_OUT_OF_RANGE:
        bin->header.shstrndx = 2;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_PHNUM_ZERO:
        bin->header.phnum = 0;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_PHNUM_XNUM:
        bin->header.phnum = N00B_TEST_ELF_PN_XNUM;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_PHOFF_WRAP:
        bin->header.phoff = UINT64_MAX - 16;
        break;
    case N00B_TEST_ELF_TARGET_MUTATION_NONE:
    case N00B_TEST_ELF_TARGET_MUTATION_SHSTRTAB_WRONG_TYPE:
    case N00B_TEST_ELF_TARGET_MUTATION_SHSTRTAB_INVALID_SIZE:
    case N00B_TEST_ELF_TARGET_MUTATION_SHSTRTAB_OFFSET_WRAP:
    case N00B_TEST_ELF_TARGET_MUTATION_SECTION_NAME_INDEX:
    case N00B_TEST_ELF_TARGET_MUTATION_EXISTING_RESERVED_SECTION_NAME:
        break;
    }
}

static void
check_target_profile_case(const n00b_test_elf_case_t *test_case)
{
    n00b_buffer_t *buf = n00b_test_elf_minimal_exec(0x400080,
                                                    0,
                                                    0x400000,
                                                    512,
                                                    512,
                                                    false,
                                                    false,
                                                    true,
                                                    false);
    N00B_TEST_REQUIRE(buf != nullptr);

    n00b_elf_binary_t *bin = nullptr;
    N00B_TEST_REQUIRE(parse_succeeds(buf, &bin));
    N00B_TEST_REQUIRE(bin != nullptr);

    n00b_test_elf_apply_target_mutation(buf, test_case->target_mutation);
    mirror_target_mutation_to_header(bin, test_case->target_mutation,
                                     buf->byte_len);

    auto profile_result = n00b_elf_rewrite_target_profile(bin);
    N00B_TEST_REQUIRE(n00b_result_is_ok(profile_result));
    n00b_elf_rewrite_target_profile_t profile =
        n00b_result_get(profile_result);

    N00B_TEST_REQUIRE(profile.reason == test_case->target_profile_reason);
    N00B_TEST_REQUIRE(profile.packager_errcode
                      == test_case->target_profile_packager_errcode);

    n00b_elf_rewrite_metadata_request_t request =
        rewrite_request_make(N00B_TEST_ELF_REWRITE_RELAXED_EOF);
    auto plan_result = n00b_elf_rewrite_plan_metadata_insert(bin, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));

    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED);
    N00B_TEST_REQUIRE(plan->rejection_reason
                      == N00B_ELF_REWRITE_REJECT_TARGET_PROFILE);
    N00B_TEST_REQUIRE(plan->target_profile.reason
                      == test_case->target_profile_reason);
    N00B_TEST_REQUIRE(plan->target_profile.packager_errcode
                      == test_case->target_profile_packager_errcode);
}

static void
check_rewrite_case(const n00b_test_elf_case_t *test_case)
{
    n00b_buffer_t *buf = n00b_test_elf_case_generate(test_case);
    N00B_TEST_REQUIRE(buf != nullptr);

    n00b_elf_binary_t *bin = nullptr;
    N00B_TEST_REQUIRE(parse_succeeds(buf, &bin));
    N00B_TEST_REQUIRE(bin != nullptr);

    n00b_elf_rewrite_metadata_request_t request =
        rewrite_request_make(test_case->rewrite_request);
    auto plan_result = n00b_elf_rewrite_plan_metadata_insert(bin, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));

    n00b_elf_rewrite_plan_t *plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == test_case->rewrite_outcome);
    N00B_TEST_REQUIRE(plan->rejection_reason == test_case->rewrite_reason);
    N00B_TEST_REQUIRE(plan->admission.rejection_reason
                      == test_case->rewrite_admission_reason);
    N00B_TEST_REQUIRE(rewrite_plan_placement_kind(plan)
                      == test_case->rewrite_admission_placement);
    N00B_TEST_REQUIRE(plan->table_strategy == test_case->rewrite_table_strategy);

    if (plan->outcome == N00B_ELF_REWRITE_PLAN_REJECTED) {
        auto rejected = n00b_elf_rewrite_apply_metadata_insert_plan(bin, plan);
        N00B_TEST_REQUIRE(n00b_result_is_err(rejected));
        N00B_TEST_REQUIRE(n00b_result_get_err(rejected)
                          == N00B_ELF_REWRITE_ERR_PLAN_REJECTED);
        return;
    }

    N00B_TEST_REQUIRE(plan->new_section_count
                      == plan->original_section_count + 1);
    auto applied = n00b_elf_rewrite_apply_metadata_insert_plan(bin, plan);
    N00B_TEST_REQUIRE(n00b_result_is_ok(applied));

    n00b_buffer_t *out = n00b_result_get(applied);
    n00b_elf_binary_t *rewritten = nullptr;
    N00B_TEST_REQUIRE(parse_succeeds(out, &rewritten));
    N00B_TEST_REQUIRE(rewritten != nullptr);
    assert_inserted_section(rewritten, plan, &request);
}

static void
check_loadable_case(const n00b_test_elf_case_t *test_case)
{
    n00b_buffer_t *buf = n00b_test_elf_case_generate(test_case);
    N00B_TEST_REQUIRE(buf != nullptr);

    n00b_elf_binary_t *bin = nullptr;
    N00B_TEST_REQUIRE(parse_succeeds(buf, &bin));
    N00B_TEST_REQUIRE(bin != nullptr);

    n00b_elf_rewrite_loadable_request_t request =
        loadable_request_make(test_case->loadable_request);
    auto plan_result = n00b_elf_rewrite_plan_loadable_insert(bin, &request);
    N00B_TEST_REQUIRE(n00b_result_is_ok(plan_result));

    n00b_elf_rewrite_loadable_plan_t *plan = n00b_result_get(plan_result);
    N00B_TEST_REQUIRE(plan->outcome == test_case->loadable_outcome);
    N00B_TEST_REQUIRE(plan->rejection_reason == test_case->loadable_reason);
    N00B_TEST_REQUIRE(plan->admission.rejection_reason
                      == test_case->loadable_admission_reason);
    if (plan->phtab_strategy != test_case->loadable_phtab_strategy) {
        fprintf(stderr,
                "loadable phtab strategy mismatch: case=%s expected=%d got=%d\n",
                test_case->name,
                (int)test_case->loadable_phtab_strategy,
                (int)plan->phtab_strategy);
        N00B_TEST_REQUIRE(false);
    }
    N00B_TEST_REQUIRE(plan->phtab_adjustment.status
                      == test_case->loadable_phtab_adjust_status);
    N00B_TEST_REQUIRE(plan->phtab_adjustment.rejection_reason
                      == test_case->loadable_phtab_adjust_reason);
    N00B_TEST_REQUIRE(plan->phtab_relocation.status
                      == test_case->loadable_relocation_status);
    N00B_TEST_REQUIRE(plan->phtab_relocation.rejection_reason
                      == test_case->loadable_relocation_reason);

    if (plan->phtab_relocation.status
        == N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED) {
        N00B_TEST_REQUIRE(plan->phtab_placement.kind
                          == N00B_ELF_REWRITE_LOADABLE_PLACEMENT_RELOCATED_PHTAB);
        N00B_TEST_REQUIRE(plan->payload_placement.kind
                          == N00B_ELF_REWRITE_LOADABLE_PLACEMENT_LOADABLE_PAYLOAD);
        N00B_TEST_REQUIRE(plan->patches.len >= 3);
    }

    if (test_case->loadable_apply_reparse) {
        auto applied = n00b_elf_rewrite_apply_loadable_insert_plan(bin, plan);
        N00B_TEST_REQUIRE(n00b_result_is_ok(applied));

        n00b_buffer_t *out = n00b_result_get(applied);
        n00b_elf_binary_t *rewritten = nullptr;
        N00B_TEST_REQUIRE(parse_succeeds(out, &rewritten));
        N00B_TEST_REQUIRE(rewritten != nullptr);
        N00B_TEST_REQUIRE(rewritten->header.phnum == bin->header.phnum + 1);
        N00B_TEST_REQUIRE(rewritten->header.entry == bin->header.entry);
        N00B_TEST_REQUIRE(rewritten->header.shoff == bin->header.shoff);
        N00B_TEST_REQUIRE(rewritten->num_segments == bin->num_segments + 1);
        assert_rewritten_loadable_payload(out, plan, request.payload);
        assert_loadable_padding_zeroed(out, plan);
        assert_unplanned_original_loadable_bytes_preserved(buf, out, plan);

        if (plan->phtab_strategy
            == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST) {
            n00b_elf_rewrite_loadable_phtab_adjustment_t *adj =
                &plan->phtab_adjustment;
            n00b_elf_segment_t *old_load =
                &bin->segments[adj->containing_load_index];
            n00b_elf_segment_t *new_load =
                &rewritten->segments[adj->containing_load_index];
            n00b_elf_segment_t *pt_phdr =
                &rewritten->segments[adj->pt_phdr_index];

            N00B_TEST_REQUIRE(rewritten->header.phoff
                              == adj->adjusted_phtab_offset);
            N00B_TEST_REQUIRE(new_load->filesz
                              == old_load->filesz
                               + adj->required_file_extension);
            N00B_TEST_REQUIRE(new_load->memsz
                              == old_load->memsz
                               + adj->required_memory_extension);
            N00B_TEST_REQUIRE(pt_phdr->type == PT_PHDR);
            N00B_TEST_REQUIRE(pt_phdr->offset == adj->pt_phdr_new_offset);
            N00B_TEST_REQUIRE(pt_phdr->filesz == adj->pt_phdr_new_filesz);
            N00B_TEST_REQUIRE(pt_phdr->memsz == adj->pt_phdr_new_memsz);
            N00B_TEST_REQUIRE(pt_phdr->vaddr == adj->pt_phdr_new_vaddr);
            N00B_TEST_REQUIRE(pt_phdr->paddr == adj->pt_phdr_new_vaddr);

            assert_rewritten_new_pt_load(rewritten,
                                         plan,
                                         plan->payload_placement.file_offset,
                                         plan->payload_placement.vaddr,
                                         plan->payload_placement.vaddr,
                                         request.payload->byte_len,
                                         plan->p_memsz,
                                         plan->payload_placement.alignment);
        }
        else if (plan->phtab_strategy
                 == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE) {
            n00b_elf_rewrite_loadable_relocation_t *rel =
                &plan->phtab_relocation;
            n00b_elf_segment_t *pt_phdr =
                &rewritten->segments[rel->pt_phdr_index];

            N00B_TEST_REQUIRE(rewritten->header.phoff
                              == rel->relocated_phtab_offset);
            N00B_TEST_REQUIRE(pt_phdr->type == PT_PHDR);
            N00B_TEST_REQUIRE(pt_phdr->offset == rel->pt_phdr_new_offset);
            N00B_TEST_REQUIRE(pt_phdr->filesz == rel->pt_phdr_new_filesz);
            N00B_TEST_REQUIRE(pt_phdr->memsz == rel->pt_phdr_new_memsz);
            N00B_TEST_REQUIRE(pt_phdr->vaddr == rel->pt_phdr_new_vaddr);
            N00B_TEST_REQUIRE(pt_phdr->paddr == rel->pt_phdr_new_paddr);

            assert_rewritten_new_pt_load(rewritten,
                                         plan,
                                         rel->new_pt_load_offset,
                                         rel->new_pt_load_vaddr,
                                         rel->new_pt_load_paddr,
                                         rel->new_pt_load_filesz,
                                         rel->new_pt_load_memsz,
                                         rel->new_pt_load_align);
        }
    }
}

static void
test_target_profile_known_answers(void)
{
    bool saw[N00B_TEST_ELF_TARGET_MUTATION_EXISTING_RESERVED_SECTION_NAME + 1] = {0};
    size_t count = 0;

    for (size_t i = 0; i < n00b_test_elf_case_count; i++) {
        const n00b_test_elf_case_t *test_case = &n00b_test_elf_cases[i];

        if (!n00b_test_elf_case_has_target_profile(test_case)) {
            continue;
        }

        check_target_profile_case(test_case);
        saw[test_case->target_mutation] = true;
        count++;
    }

    N00B_TEST_REQUIRE(count > 0);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_INVALID_EHSIZE]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_INVALID_SHENTSIZE]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_INVALID_PHENTSIZE]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_SHNUM_ZERO]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_SHNUM_ONE]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_SHNUM_LORESERVE]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_SHNUM_XINDEX]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_SHOFF_ZERO]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_SHOFF_OUT_OF_BOUNDS]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_SHOFF_WRAP]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_ZERO]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_LORESERVE]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_XINDEX]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_SHSTRNDX_OUT_OF_RANGE]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_SHSTRTAB_WRONG_TYPE]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_SHSTRTAB_INVALID_SIZE]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_SHSTRTAB_OFFSET_WRAP]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_SECTION_NAME_INDEX]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_PHNUM_ZERO]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_PHNUM_XNUM]);
    N00B_TEST_REQUIRE(saw[N00B_TEST_ELF_TARGET_MUTATION_PHOFF_WRAP]);
}

static void
test_rewrite_known_answers(void)
{
    bool saw_eof_success = false;
    bool saw_gap_success = false;
    bool saw_overlay_reject = false;
    bool saw_overlay_append = false;
    bool saw_reserved_request = false;
    bool saw_existing_reserved = false;
    size_t count = 0;

    for (size_t i = 0; i < n00b_test_elf_case_count; i++) {
        const n00b_test_elf_case_t *test_case = &n00b_test_elf_cases[i];

        if (!n00b_test_elf_case_has_rewrite(test_case)) {
            continue;
        }

        check_rewrite_case(test_case);

        if (test_case->rewrite_request == N00B_TEST_ELF_REWRITE_RELAXED_EOF
            && test_case->rewrite_outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED) {
            saw_eof_success = true;
        }
        if (test_case->rewrite_request
                == N00B_TEST_ELF_REWRITE_RELAXED_PREFERRED_GAP
            && test_case->rewrite_outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED) {
            saw_gap_success = true;
        }
        if (test_case->rewrite_request
                == N00B_TEST_ELF_REWRITE_RELAXED_OVERLAY_PRESERVE
            && test_case->rewrite_outcome == N00B_ELF_REWRITE_PLAN_REJECTED) {
            saw_overlay_reject = true;
        }
        if (test_case->rewrite_request
                == N00B_TEST_ELF_REWRITE_RELAXED_OVERLAY_APPEND
            && test_case->rewrite_outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED) {
            saw_overlay_append = true;
        }
        if (test_case->rewrite_request
            == N00B_TEST_ELF_REWRITE_RESERVED_REQUESTED_NAME) {
            saw_reserved_request = true;
        }
        if (test_case->target_mutation
            == N00B_TEST_ELF_TARGET_MUTATION_EXISTING_RESERVED_SECTION_NAME) {
            saw_existing_reserved = true;
        }
        count++;
    }

    N00B_TEST_REQUIRE(count > 0);
    N00B_TEST_REQUIRE(saw_eof_success);
    N00B_TEST_REQUIRE(saw_gap_success);
    N00B_TEST_REQUIRE(saw_overlay_reject);
    N00B_TEST_REQUIRE(saw_overlay_append);
    N00B_TEST_REQUIRE(saw_reserved_request);
    N00B_TEST_REQUIRE(saw_existing_reserved);
}

static void
test_loadable_known_answers(void)
{
    bool saw_in_place_accept = false;
    bool saw_memory_collision = false;
    bool saw_file_collision = false;
    bool saw_nonzero_slack = false;
    bool saw_at_eof = false;
    bool saw_pn_xnum = false;
    bool saw_missing_pt_phdr = false;
    bool saw_inconsistent_pt_phdr = false;
    bool saw_direct_relocation = false;
    bool saw_fallback_relocation = false;
    bool saw_placement_reject = false;
    bool saw_address_reject = false;
    bool saw_in_place_apply = false;
    bool saw_relocated_apply = false;
    size_t count = 0;

    for (size_t i = 0; i < n00b_test_elf_case_count; i++) {
        const n00b_test_elf_case_t *test_case = &n00b_test_elf_cases[i];

        if (!n00b_test_elf_case_has_loadable(test_case)) {
            continue;
        }

        check_loadable_case(test_case);

        switch (test_case->loadable_phtab_adjust_reason) {
        case N00B_ELF_REWRITE_ADMIT_REJECT_NONE:
            if (test_case->loadable_phtab_strategy
                == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST) {
                saw_in_place_accept = true;
            }
            break;
        case N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_MEMORY_COLLISION:
            saw_memory_collision = true;
            break;
        case N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_FILE_COLLISION:
            saw_file_collision = true;
            break;
        case N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_NONZERO_SLACK:
            saw_nonzero_slack = true;
            break;
        case N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_AT_EOF:
            saw_at_eof = true;
            break;
        default:
            break;
        }
        switch (test_case->loadable_admission_reason) {
        case N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_MISSING:
            saw_missing_pt_phdr = true;
            break;
        case N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_INCONSISTENT:
            saw_inconsistent_pt_phdr = true;
            break;
        default:
            break;
        }
        if (test_case->target_profile_reason
                == N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_PXNUM
            && test_case->loadable_reason
                   == N00B_ELF_REWRITE_REJECT_TARGET_PROFILE) {
            saw_pn_xnum = true;
        }
        if (test_case->loadable_request == N00B_TEST_ELF_LOADABLE_RELOCATE
            && test_case->loadable_relocation_status
                   == N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED) {
            saw_direct_relocation = true;
        }
        if (test_case->loadable_request == N00B_TEST_ELF_LOADABLE_IN_PLACE
            && test_case->loadable_relocation_status
                   == N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED) {
            saw_fallback_relocation = true;
        }
        if (test_case->loadable_reason
            == N00B_ELF_REWRITE_REJECT_LOADABLE_PLACEMENT) {
            saw_placement_reject = true;
        }
        if (test_case->loadable_reason
            == N00B_ELF_REWRITE_REJECT_LOADABLE_ADDRESS) {
            saw_address_reject = true;
        }
        if (test_case->loadable_apply_reparse
            && test_case->loadable_phtab_strategy
                   == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST) {
            saw_in_place_apply = true;
        }
        if (test_case->loadable_apply_reparse
            && test_case->loadable_phtab_strategy
                   == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE) {
            saw_relocated_apply = true;
        }
        count++;
    }

    N00B_TEST_REQUIRE(count > 0);
    N00B_TEST_REQUIRE(saw_in_place_accept);
    N00B_TEST_REQUIRE(saw_memory_collision);
    N00B_TEST_REQUIRE(saw_file_collision);
    N00B_TEST_REQUIRE(saw_nonzero_slack);
    N00B_TEST_REQUIRE(saw_at_eof);
    N00B_TEST_REQUIRE(saw_pn_xnum);
    N00B_TEST_REQUIRE(saw_missing_pt_phdr);
    N00B_TEST_REQUIRE(saw_inconsistent_pt_phdr);
    N00B_TEST_REQUIRE(saw_direct_relocation);
    N00B_TEST_REQUIRE(saw_fallback_relocation);
    N00B_TEST_REQUIRE(saw_placement_reject);
    N00B_TEST_REQUIRE(saw_address_reject);
    N00B_TEST_REQUIRE(saw_in_place_apply);
    N00B_TEST_REQUIRE(saw_relocated_apply);
}

static void
test_oracle_mode_metadata(void)
{
    N00B_TEST_REQUIRE(strcmp(n00b_test_elf_oracle_mode_arg(
                                 N00B_TEST_ELF_ORACLE_PHTAB_ADJUSTMENT),
                             "phtab-adjustment") == 0);
    N00B_TEST_REQUIRE(strcmp(n00b_test_elf_oracle_expect_name(
                                 N00B_TEST_ELF_ORACLE_PHTAB_ADJUSTABLE),
                             "phtab-adjustable") == 0);
    N00B_TEST_REQUIRE(strcmp(n00b_test_elf_oracle_expect_name(
                                 N00B_TEST_ELF_ORACLE_PHTAB_NOT_ADJUSTABLE),
                             "phtab-not-adjustable") == 0);

    bool saw_phtab_mode = false;
    for (size_t i = 0; i < n00b_test_elf_case_count; i++) {
        if (n00b_test_elf_cases[i].oracle_mode
            == N00B_TEST_ELF_ORACLE_PHTAB_ADJUSTMENT) {
            saw_phtab_mode = true;
            N00B_TEST_REQUIRE(n00b_test_elf_cases[i].loadable_request
                              != N00B_TEST_ELF_LOADABLE_NONE);
        }
    }

    N00B_TEST_REQUIRE(saw_phtab_mode);
}

static void
test_known_answers(void)
{
    size_t count = 0;

    for (size_t i = 0; i < n00b_test_elf_case_count; i++) {
        const n00b_test_elf_case_t *test_case = &n00b_test_elf_cases[i];

        if (test_case->state != N00B_TEST_ELF_CASE_KNOWN) {
            continue;
        }

        if (n00b_test_elf_case_has_target_profile(test_case)) {
            continue;
        }

        check_known_case(test_case);
        count++;
    }

    assert(count > 0);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running ELF known-answer tests...\n");
    test_known_answers();
    test_divergence_classification_metadata();
    test_layout_known_answers();
    test_admission_known_answers();
    test_target_profile_known_answers();
    test_rewrite_known_answers();
    test_loadable_known_answers();
    test_oracle_mode_metadata();
    printf("All ELF known-answer tests passed.\n");
    return 0;
}
