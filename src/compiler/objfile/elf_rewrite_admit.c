#include "compiler/objfile/elf_rewrite_admit.h"

#include "compiler/objfile/elf_layout.h"
#include "text/strings/string_ops.h"

#define N00B_ELF_SHT_CRASHOVERRIDE_GUARD 0xc001u
#define N00B_ELF_PN_XNUM 0xffffu
#define N00B_ELF64_PHDR_SIZE 56u
#define N00B_ELF64_PHDR_ALIGN 8u
#define N00B_ELF_LOAD_PAGE_SIZE 0x1000u

typedef struct phtab_range {
    bool     present;
    uint64_t start;
    uint64_t end;
    uint64_t size;
} phtab_range_t;

typedef enum {
    TRUSTED_METADATA_NONE,
    TRUSTED_METADATA_CHALK_MARK,
    TRUSTED_METADATA_OBJECT_BUNDLE,
} trusted_metadata_kind_t;

static bool
checked_add_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (UINT64_MAX - a < b) {
        return false;
    }

    *out = a + b;
    return true;
}

static bool
checked_mul_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a != 0 && b > UINT64_MAX / a) {
        return false;
    }

    *out = a * b;
    return true;
}

static bool
validate_packager_bounds(uint64_t obj_size,
                         uint64_t obj_offset,
                         uint64_t file_size)
{
    uint64_t end;

    if (!checked_add_u64(obj_size, obj_offset, &end)) {
        return false;
    }

    return end > obj_size && end <= file_size;
}

static uint64_t
effective_alignment(uint64_t requested)
{
    if (requested == 0) {
        return 1;
    }

    return requested;
}

static uint64_t
pad8(uint64_t value)
{
    return (8 - (value & 7u)) & 7u;
}

static n00b_err_t
layout_err_to_admit_err(n00b_err_t err)
{
    if (err == N00B_ELF_LAYOUT_ERR_OVERFLOW) {
        return N00B_ELF_REWRITE_ADMIT_ERR_OVERFLOW;
    }

    return N00B_ELF_REWRITE_ADMIT_ERR_LAYOUT_SUBSTRATE;
}

static bool
policy_has(n00b_elf_rewrite_admit_policy_t policy,
           n00b_elf_rewrite_admit_policy_flag_t flag)
{
    return (policy.flags & (uint64_t)flag) != 0;
}

static bool
policy_allows_append_after_overlay(n00b_elf_rewrite_admit_policy_t policy)
{
    return policy_has(policy, N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY)
        && policy_has(policy, N00B_ELF_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY);
}

static n00b_elf_rewrite_admit_result_t
make_result(n00b_elf_layout_t                         *layout,
            n00b_elf_rewrite_admit_metadata_request_t *request,
            uint64_t                                   alignment,
            n00b_elf_rewrite_admit_outcome_t           outcome,
            n00b_elf_rewrite_admit_rejection_reason_t  reason,
            n00b_option_t(n00b_elf_rewrite_admit_placement_t) placement)
{
    return (n00b_elf_rewrite_admit_result_t){
        .outcome             = outcome,
        .rejection_reason    = reason,
        .placement           = placement,
        .file_size           = layout->file_size,
        .effective_alignment = alignment,
        .policy              = request->policy,
    };
}

static n00b_result_t(n00b_elf_rewrite_admit_result_t)
accepted(n00b_elf_layout_t                         *layout,
         n00b_elf_rewrite_admit_metadata_request_t *request,
         uint64_t                                   alignment,
         n00b_elf_rewrite_admit_placement_t         placement)
{
    n00b_elf_rewrite_admit_result_t result = make_result(
        layout,
        request,
        alignment,
        N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED,
        N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        n00b_option_set(n00b_elf_rewrite_admit_placement_t, placement));

    return n00b_result_ok(n00b_elf_rewrite_admit_result_t, result);
}

static n00b_result_t(n00b_elf_rewrite_admit_result_t)
rejected(n00b_elf_layout_t                         *layout,
         n00b_elf_rewrite_admit_metadata_request_t *request,
         uint64_t                                   alignment,
         n00b_elf_rewrite_admit_rejection_reason_t  reason)
{
    n00b_elf_rewrite_admit_result_t result = make_result(
        layout,
        request,
        alignment,
        N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED,
        reason,
        n00b_option_none(n00b_elf_rewrite_admit_placement_t));

    return n00b_result_ok(n00b_elf_rewrite_admit_result_t, result);
}

static bool
section_name_is_reserved(n00b_string_t *name)
{
    if (n00b_unicode_str_starts_with(name, r".chalk.")) {
        return true;
    }

    return n00b_unicode_str_starts_with(name, r".0c001.");
}

static bool
section_name_is_chalk_mark(n00b_string_t *name)
{
    return n00b_unicode_str_eq(name, r".chalk.mark");
}

static bool
section_name_is_chalk_free(n00b_string_t *name)
{
    return n00b_unicode_str_eq(name, r".chalk.free");
}

static bool
section_name_is_object_bundle(n00b_string_t *name)
{
    return n00b_unicode_str_eq(name, r".0c001.bundle");
}

static bool
section_name_matches_trusted_kind(n00b_string_t *name,
                                  trusted_metadata_kind_t kind)
{
    switch (kind) {
    case TRUSTED_METADATA_NONE:
        return false;
    case TRUSTED_METADATA_CHALK_MARK:
        return section_name_is_chalk_mark(name);
    case TRUSTED_METADATA_OBJECT_BUNDLE:
        return section_name_is_object_bundle(name);
    }

    return false;
}

static bool
target_has_reserved_section_for_trusted_kind(n00b_elf_binary_t       *bin,
                                             trusted_metadata_kind_t  trusted_kind)
{
    for (uint32_t i = 0; i < bin->num_sections; i++) {
        n00b_elf_section_t *sec = &bin->sections[i];

        if (sec->type == N00B_ELF_SHT_CRASHOVERRIDE_GUARD) {
            return true;
        }

        if (sec->name != nullptr
            && trusted_kind == TRUSTED_METADATA_OBJECT_BUNDLE
            && (section_name_is_chalk_mark(sec->name)
                || section_name_is_chalk_free(sec->name))) {
            continue;
        }

        if (sec->name != nullptr && section_name_is_reserved(sec->name)) {
            return true;
        }
    }

    return false;
}

static bool
target_has_reserved_section(n00b_elf_binary_t *bin)
{
    return target_has_reserved_section_for_trusted_kind(
        bin,
        TRUSTED_METADATA_NONE);
}

static bool
request_is_metadata_only(n00b_elf_rewrite_admit_metadata_request_t *request)
{
    if (request->section_flags != 0) {
        return false;
    }

    switch (request->section_type) {
    case SHT_PROGBITS:
    case SHT_NOTE:
        return true;
    default:
        return false;
    }
}

static bool
request_is_metadata_for_trusted_kind(
    n00b_elf_rewrite_admit_metadata_request_t *request,
    trusted_metadata_kind_t                    kind)
{
    if (kind != TRUSTED_METADATA_OBJECT_BUNDLE) {
        return request_is_metadata_only(request);
    }

    return request->section_flags == 0
        && request->section_type == SHT_PROGBITS;
}

static n00b_result_t(phtab_range_t)
get_phtab_range(n00b_elf_binary_t *bin)
{
    phtab_range_t range = {};

    if (bin->header.phoff == 0 || bin->header.phnum == 0
        || bin->header.phentsize == 0) {
        return n00b_result_ok(phtab_range_t, range);
    }

    if (!checked_mul_u64(bin->header.phentsize, bin->header.phnum,
                         &range.size)) {
        return n00b_result_err(phtab_range_t,
                               N00B_ELF_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    if (!checked_add_u64(bin->header.phoff, range.size, &range.end)) {
        return n00b_result_err(phtab_range_t,
                               N00B_ELF_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    range.present = range.size != 0;
    range.start   = bin->header.phoff;
    return n00b_result_ok(phtab_range_t, range);
}

static n00b_result_t(n00b_option_t(uint64_t))
load_vaddr_for_file_range(n00b_elf_binary_t *bin,
                          uint64_t           start,
                          uint64_t           end)
{
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_elf_segment_t *seg = &bin->segments[i];

        if (seg->type != PT_LOAD || start < seg->offset) {
            continue;
        }

        uint64_t seg_file_end;
        if (!checked_add_u64(seg->offset, seg->filesz, &seg_file_end)) {
            return n00b_result_err(n00b_option_t(uint64_t),
                                   N00B_ELF_REWRITE_ADMIT_ERR_OVERFLOW);
        }

        if (end > seg_file_end) {
            continue;
        }

        uint64_t delta = start - seg->offset;
        uint64_t vaddr;
        if (!checked_add_u64(seg->vaddr, delta, &vaddr)) {
            return n00b_result_err(n00b_option_t(uint64_t),
                                   N00B_ELF_REWRITE_ADMIT_ERR_OVERFLOW);
        }

        return n00b_result_ok(n00b_option_t(uint64_t),
                              n00b_option_set(uint64_t, vaddr));
    }

    return n00b_result_ok(n00b_option_t(uint64_t),
                          n00b_option_none(uint64_t));
}

static n00b_result_t(n00b_elf_rewrite_admit_rejection_reason_t)
check_pt_phdr(n00b_elf_binary_t        *bin,
              phtab_range_t             phtab,
              n00b_option_t(uint64_t)   phtab_vaddr)
{
    bool saw_pt_phdr = false;

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_elf_segment_t *seg = &bin->segments[i];

        if (seg->type != PT_PHDR) {
            continue;
        }

        if (saw_pt_phdr || !phtab.present
            || !n00b_option_is_set(phtab_vaddr)
            || seg->offset != phtab.start
            || seg->filesz != phtab.size
            || seg->memsz != phtab.size
            || seg->vaddr != n00b_option_get(phtab_vaddr)) {
            return n00b_result_ok(
                n00b_elf_rewrite_admit_rejection_reason_t,
                N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_INCONSISTENT);
        }

        saw_pt_phdr = true;
    }

    if (!saw_pt_phdr) {
        return n00b_result_ok(n00b_elf_rewrite_admit_rejection_reason_t,
                              N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_MISSING);
    }

    return n00b_result_ok(n00b_elf_rewrite_admit_rejection_reason_t,
                          N00B_ELF_REWRITE_ADMIT_REJECT_NONE);
}

static n00b_result_t(n00b_elf_rewrite_admit_rejection_reason_t)
check_entrypoint(n00b_elf_binary_t *bin)
{
    if (bin->header.entry == 0) {
        return n00b_result_ok(n00b_elf_rewrite_admit_rejection_reason_t,
                              N00B_ELF_REWRITE_ADMIT_REJECT_NONE);
    }

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_elf_segment_t *seg = &bin->segments[i];

        if (seg->type != PT_LOAD || (seg->flags & PF_X) == 0
            || bin->header.entry < seg->vaddr) {
            continue;
        }

        uint64_t mem_end;
        if (!checked_add_u64(seg->vaddr, seg->memsz, &mem_end)) {
            return n00b_result_err(n00b_elf_rewrite_admit_rejection_reason_t,
                                   N00B_ELF_REWRITE_ADMIT_ERR_OVERFLOW);
        }

        if (bin->header.entry >= mem_end) {
            continue;
        }

        uint64_t delta = bin->header.entry - seg->vaddr;
        if (delta >= seg->filesz) {
            return n00b_result_ok(
                n00b_elf_rewrite_admit_rejection_reason_t,
                N00B_ELF_REWRITE_ADMIT_REJECT_ENTRY_MEMORY_ONLY);
        }

        return n00b_result_ok(n00b_elf_rewrite_admit_rejection_reason_t,
                              N00B_ELF_REWRITE_ADMIT_REJECT_NONE);
    }

    return n00b_result_ok(n00b_elf_rewrite_admit_rejection_reason_t,
                          N00B_ELF_REWRITE_ADMIT_REJECT_ENTRY_OUTSIDE_LOAD);
}

static n00b_result_t(n00b_elf_rewrite_admit_rejection_reason_t)
check_loader_preservation(n00b_elf_binary_t *bin)
{
    auto phtab_result = get_phtab_range(bin);
    if (n00b_result_is_err(phtab_result)) {
        return n00b_result_err(n00b_elf_rewrite_admit_rejection_reason_t,
                               n00b_result_get_err(phtab_result));
    }

    phtab_range_t phtab = n00b_result_get(phtab_result);
    n00b_option_t(uint64_t) phtab_vaddr = n00b_option_none(uint64_t);

    if (phtab.present) {
        auto vaddr_result = load_vaddr_for_file_range(bin,
                                                      phtab.start,
                                                      phtab.end);
        if (n00b_result_is_err(vaddr_result)) {
            return n00b_result_err(n00b_elf_rewrite_admit_rejection_reason_t,
                                   n00b_result_get_err(vaddr_result));
        }

        phtab_vaddr = n00b_result_get(vaddr_result);
        if (!n00b_option_is_set(phtab_vaddr)) {
            return n00b_result_ok(
                n00b_elf_rewrite_admit_rejection_reason_t,
                N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_OUTSIDE_LOAD);
        }
    }

    auto phdr_reason = check_pt_phdr(bin, phtab, phtab_vaddr);
    if (n00b_result_is_err(phdr_reason)
        || n00b_result_get(phdr_reason)
               != N00B_ELF_REWRITE_ADMIT_REJECT_NONE) {
        return phdr_reason;
    }

    return check_entrypoint(bin);
}

static bool
collision_has_overlay(n00b_elf_layout_collision_t *collision)
{
    for (uint64_t i = 0; i < collision->interval_count; i++) {
        if (collision->intervals[i].kind == N00B_ELF_LAYOUT_INTERVAL_OVERLAY) {
            return true;
        }
    }

    return false;
}

static n00b_elf_rewrite_admit_placement_t
placement_from_range(n00b_elf_rewrite_admit_placement_kind_t kind,
                     uint64_t                                start,
                     uint64_t                                end,
                     uint64_t                                payload_size,
                     uint64_t                                alignment)
{
    return (n00b_elf_rewrite_admit_placement_t){
        .kind           = kind,
        .file_offset    = start,
        .file_end       = end,
        .payload_size   = payload_size,
        .file_alignment = alignment,
    };
}

static n00b_result_t(n00b_elf_rewrite_admit_result_t)
admit_preferred_placement(n00b_elf_binary_t                         *bin,
                          n00b_elf_layout_t                         *layout,
                          n00b_elf_rewrite_admit_metadata_request_t *request,
                          uint64_t                                   alignment,
                          n00b_allocator_t                          *allocator)
{
    uint64_t start = n00b_option_get(request->preferred_file_offset);
    if (start % alignment != 0) {
        return rejected(layout,
                        request,
                        alignment,
                        N00B_ELF_REWRITE_ADMIT_REJECT_NO_SAFE_PLACEMENT);
    }

    uint64_t end;
    if (!checked_add_u64(start, request->payload_size, &end)) {
        return n00b_result_err(n00b_elf_rewrite_admit_result_t,
                               N00B_ELF_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    auto collision_result = n00b_elf_layout_file_collision(layout,
                                                           start,
                                                           end,
                                                           .allocator = allocator);
    if (n00b_result_is_err(collision_result)) {
        return n00b_result_err(
            n00b_elf_rewrite_admit_result_t,
            layout_err_to_admit_err(n00b_result_get_err(collision_result)));
    }

    n00b_elf_layout_collision_t collision = n00b_result_get(collision_result);
    if (collision.interval_count != 0) {
        if (collision_has_overlay(&collision)) {
            return rejected(
                layout,
                request,
                alignment,
                N00B_ELF_REWRITE_ADMIT_REJECT_OVERLAY_POLICY);
        }

        return rejected(layout,
                        request,
                        alignment,
                        N00B_ELF_REWRITE_ADMIT_REJECT_FILE_COLLISION);
    }

    auto gap_result = n00b_elf_layout_find_file_gap(layout,
                                                    start,
                                                    end,
                                                    request->payload_size,
                                                    alignment);
    if (n00b_result_is_err(gap_result)) {
        return n00b_result_err(
            n00b_elf_rewrite_admit_result_t,
            layout_err_to_admit_err(n00b_result_get_err(gap_result)));
    }

    n00b_option_t(n00b_elf_layout_gap_t) gap_opt = n00b_result_get(gap_result);
    if (!n00b_option_is_set(gap_opt)) {
        return rejected(layout,
                        request,
                        alignment,
                        N00B_ELF_REWRITE_ADMIT_REJECT_NO_SAFE_PLACEMENT);
    }

    n00b_elf_layout_gap_t gap = n00b_option_get(gap_opt);
    if (gap.start != start || gap.end < end) {
        return rejected(layout,
                        request,
                        alignment,
                        N00B_ELF_REWRITE_ADMIT_REJECT_NO_SAFE_PLACEMENT);
    }

    switch (gap.kind) {
    case N00B_ELF_LAYOUT_GAP_ZERO_PADDING:
        return accepted(
            layout,
            request,
            alignment,
            placement_from_range(
                N00B_ELF_REWRITE_ADMIT_PLACEMENT_FILE_GAP,
                start,
                end,
                request->payload_size,
                alignment));
    case N00B_ELF_LAYOUT_GAP_UNKNOWN_NONZERO:
        return rejected(
            layout,
            request,
            alignment,
            N00B_ELF_REWRITE_ADMIT_REJECT_UNKNOWN_NONZERO_BYTES);
    case N00B_ELF_LAYOUT_GAP_OVERLAY:
        return rejected(
            layout,
            request,
            alignment,
            N00B_ELF_REWRITE_ADMIT_REJECT_OVERLAY_POLICY);
    case N00B_ELF_LAYOUT_GAP_EOF_TAIL:
        if (bin->overlay != nullptr) {
            if (!policy_allows_append_after_overlay(request->policy)) {
                return rejected(
                    layout,
                    request,
                    alignment,
                    N00B_ELF_REWRITE_ADMIT_REJECT_OVERLAY_POLICY);
            }

            return accepted(
                layout,
                request,
                alignment,
                placement_from_range(
                    N00B_ELF_REWRITE_ADMIT_PLACEMENT_AFTER_OVERLAY,
                    gap.start,
                    gap.end,
                    request->payload_size,
                    alignment));
        }

        return accepted(
            layout,
            request,
            alignment,
            placement_from_range(
                N00B_ELF_REWRITE_ADMIT_PLACEMENT_EOF_TAIL,
                gap.start,
                gap.end,
                request->payload_size,
                alignment));
    case N00B_ELF_LAYOUT_GAP_VADDR_UNMAPPED:
    default:
        return rejected(layout,
                        request,
                        alignment,
                        N00B_ELF_REWRITE_ADMIT_REJECT_NO_SAFE_PLACEMENT);
    }
}

static n00b_result_t(n00b_elf_rewrite_admit_result_t)
admit_eof_placement(n00b_elf_binary_t                         *bin,
                    n00b_elf_layout_t                         *layout,
                    n00b_elf_rewrite_admit_metadata_request_t *request,
                    uint64_t                                   alignment)
{
    if (bin->overlay != nullptr
        && !policy_allows_append_after_overlay(request->policy)) {
        return rejected(layout,
                        request,
                        alignment,
                        N00B_ELF_REWRITE_ADMIT_REJECT_OVERLAY_POLICY);
    }

    auto tail = n00b_elf_layout_eof_tail_gap(layout,
                                             request->payload_size,
                                             alignment);
    if (n00b_result_is_err(tail)) {
        return n00b_result_err(
            n00b_elf_rewrite_admit_result_t,
            layout_err_to_admit_err(n00b_result_get_err(tail)));
    }

    n00b_option_t(n00b_elf_layout_gap_t) gap_opt = n00b_result_get(tail);
    if (!n00b_option_is_set(gap_opt)) {
        return n00b_result_err(n00b_elf_rewrite_admit_result_t,
                               N00B_ELF_REWRITE_ADMIT_ERR_LAYOUT_SUBSTRATE);
    }

    n00b_elf_layout_gap_t gap = n00b_option_get(gap_opt);
    n00b_elf_rewrite_admit_placement_kind_t kind =
        bin->overlay == nullptr
            ? N00B_ELF_REWRITE_ADMIT_PLACEMENT_EOF_TAIL
            : N00B_ELF_REWRITE_ADMIT_PLACEMENT_AFTER_OVERLAY;

    return accepted(layout,
                    request,
                    alignment,
                    placement_from_range(kind,
                                         gap.start,
                                         gap.end,
                                         request->payload_size,
                                         alignment));
}

static n00b_result_t(n00b_elf_rewrite_admit_result_t)
admit_metadata_insert_impl(
    n00b_elf_binary_t                         *bin,
    n00b_elf_rewrite_admit_metadata_request_t *request,
    trusted_metadata_kind_t                    trusted_kind,
    n00b_allocator_t                          *allocator)
{
    if (bin == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_admit_result_t,
                               N00B_ELF_REWRITE_ADMIT_ERR_NULL_BINARY);
    }

    if (request == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_admit_result_t,
                               N00B_ELF_REWRITE_ADMIT_ERR_NULL_REQUEST);
    }

    if (request->section_name == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_admit_result_t,
                               N00B_ELF_REWRITE_ADMIT_ERR_NULL_SECTION_NAME);
    }

    if (request->payload_size == 0) {
        return n00b_result_err(n00b_elf_rewrite_admit_result_t,
                               N00B_ELF_REWRITE_ADMIT_ERR_ZERO_PAYLOAD_SIZE);
    }

    uint64_t alignment = effective_alignment(request->file_alignment);

    auto layout_result = n00b_elf_layout_build(bin, .allocator = allocator);
    if (n00b_result_is_err(layout_result)) {
        return n00b_result_err(
            n00b_elf_rewrite_admit_result_t,
            layout_err_to_admit_err(n00b_result_get_err(layout_result)));
    }

    n00b_elf_layout_t *layout = n00b_result_get(layout_result);

    bool requested_reserved = section_name_is_reserved(request->section_name);
    if ((trusted_kind == TRUSTED_METADATA_NONE && requested_reserved)
        || (trusted_kind != TRUSTED_METADATA_NONE
            && !section_name_matches_trusted_kind(request->section_name,
                                                 trusted_kind))
        || target_has_reserved_section_for_trusted_kind(bin, trusted_kind)) {
        return rejected(layout,
                        request,
                        alignment,
                        N00B_ELF_REWRITE_ADMIT_REJECT_RESERVED_SECTION_NAME);
    }

    if (!request_is_metadata_for_trusted_kind(request, trusted_kind)) {
        return rejected(layout,
                        request,
                        alignment,
                        N00B_ELF_REWRITE_ADMIT_REJECT_SECTION_NOT_METADATA);
    }

    if (policy_has(request->policy,
                   N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION)) {
        auto loader_reason = check_loader_preservation(bin);
        if (n00b_result_is_err(loader_reason)) {
            return n00b_result_err(n00b_elf_rewrite_admit_result_t,
                                   n00b_result_get_err(loader_reason));
        }

        n00b_elf_rewrite_admit_rejection_reason_t reason =
            n00b_result_get(loader_reason);
        if (reason != N00B_ELF_REWRITE_ADMIT_REJECT_NONE) {
            return rejected(layout, request, alignment, reason);
        }
    }

    if (n00b_option_is_set(request->preferred_file_offset)) {
        return admit_preferred_placement(bin,
                                         layout,
                                         request,
                                         alignment,
                                         allocator);
    }

    return admit_eof_placement(bin, layout, request, alignment);
}

static n00b_elf_rewrite_loadable_placement_t
deferred_loadable_placement(uint64_t alignment)
{
    return (n00b_elf_rewrite_loadable_placement_t){
        .kind      = N00B_ELF_REWRITE_LOADABLE_PLACEMENT_DEFERRED,
        .alignment = alignment,
    };
}

static n00b_elf_rewrite_loadable_placement_t
none_loadable_placement(void)
{
    return (n00b_elf_rewrite_loadable_placement_t){
        .kind = N00B_ELF_REWRITE_LOADABLE_PLACEMENT_NONE,
    };
}

static n00b_elf_rewrite_loadable_phtab_adjustment_t
no_phtab_adjustment(void)
{
    return (n00b_elf_rewrite_loadable_phtab_adjustment_t){
        .status                = N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_NONE,
        .rejection_reason      = N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
        .containing_load_index = N00B_ELF_LAYOUT_NO_INDEX,
        .pt_phdr_index         = N00B_ELF_LAYOUT_NO_INDEX,
    };
}

static n00b_elf_rewrite_loadable_phtab_adjustment_t
rejected_phtab_adjustment(
    n00b_elf_rewrite_admit_rejection_reason_t       reason,
    n00b_elf_rewrite_loadable_phtab_adjust_status_t status)
{
    n00b_elf_rewrite_loadable_phtab_adjustment_t facts =
        no_phtab_adjustment();

    facts.status           = status;
    facts.rejection_reason = reason;
    return facts;
}

static bool
rejection_is_hard_for_in_place_phtab(
    n00b_elf_rewrite_admit_rejection_reason_t reason)
{
    switch (reason) {
    case N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_MEMORY_COLLISION:
    case N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_FILE_COLLISION:
    case N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_NONZERO_SLACK:
        return false;
    default:
        return true;
    }
}

static bool
phtab_adjust_file_interval_is_modeled_elf_object(
    n00b_elf_layout_interval_t *interval)
{
    return interval->kind != N00B_ELF_LAYOUT_INTERVAL_OVERLAY;
}

static bool
phtab_adjust_collision_has_modeled_elf_object(
    n00b_elf_layout_collision_t *collision)
{
    for (uint64_t i = 0; i < collision->interval_count; i++) {
        if (phtab_adjust_file_interval_is_modeled_elf_object(
                &collision->intervals[i])) {
            return true;
        }
    }

    return false;
}

static n00b_result_t(n00b_option_t(n00b_elf_layout_interval_t))
phtab_adjust_next_modeled_file_interval(n00b_elf_layout_t *layout,
                                        uint64_t           start)
{
    uint64_t cursor = start;

    for (;;) {
        auto next_result = n00b_elf_layout_next_file_interval(layout, cursor);
        if (n00b_result_is_err(next_result)) {
            return next_result;
        }

        n00b_option_t(n00b_elf_layout_interval_t) next_opt =
            n00b_result_get(next_result);
        if (!n00b_option_is_set(next_opt)) {
            return next_result;
        }

        n00b_elf_layout_interval_t next = n00b_option_get(next_opt);
        if (phtab_adjust_file_interval_is_modeled_elf_object(&next)) {
            return next_result;
        }

        if (next.end <= cursor) {
            if (!checked_add_u64(cursor, 1, &cursor)) {
                return n00b_result_err(
                    n00b_option_t(n00b_elf_layout_interval_t),
                    N00B_ELF_LAYOUT_ERR_OVERFLOW);
            }
        } else {
            cursor = next.end;
        }
    }
}

static n00b_elf_rewrite_admit_loadable_result_t
make_loadable_result(
    n00b_elf_binary_t                         *bin,
    n00b_elf_rewrite_admit_loadable_request_t *request,
    uint64_t                                   file_alignment,
    uint64_t                                   vaddr_alignment,
    n00b_elf_rewrite_admit_outcome_t           outcome,
    n00b_elf_rewrite_admit_rejection_reason_t  reason,
    n00b_elf_rewrite_loadable_phtab_adjustment_t phtab_adjustment)
{
    uint64_t file_size = 0;
    if (bin != nullptr && bin->stream != nullptr
        && bin->stream->buf != nullptr) {
        file_size = bin->stream->buf->byte_len;
    }

    uint64_t original_count = bin == nullptr ? 0 : bin->header.phnum;
    uint64_t new_count = original_count;
    if (outcome == N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED) {
        new_count = original_count + 1;
    }

    n00b_elf_rewrite_loadable_placement_t none = none_loadable_placement();
    n00b_elf_rewrite_loadable_placement_t phtab_placement =
        outcome == N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED
            ? deferred_loadable_placement(N00B_ELF64_PHDR_ALIGN)
            : none;
    if (phtab_adjustment.status
        == N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_ACCEPTED) {
        phtab_placement = (n00b_elf_rewrite_loadable_placement_t){
            .kind        = N00B_ELF_REWRITE_LOADABLE_PLACEMENT_IN_PLACE_PHTAB,
            .file_offset = phtab_adjustment.adjusted_phtab_offset,
            .file_end    = phtab_adjustment.adjusted_phtab_offset
                         + phtab_adjustment.adjusted_phtab_size,
            .vaddr       = phtab_adjustment.adjusted_phtab_vaddr,
            .vaddr_end   = phtab_adjustment.adjusted_phtab_vaddr
                         + phtab_adjustment.adjusted_phtab_size,
            .alignment   = N00B_ELF64_PHDR_ALIGN,
        };
    }

    return (n00b_elf_rewrite_admit_loadable_result_t){
        .outcome                    = outcome,
        .rejection_reason           = reason,
        .phtab_strategy             = request->phtab_strategy,
        .payload_placement          =
            outcome == N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED
                ? deferred_loadable_placement(file_alignment)
                : none,
        .phtab_placement            =
            phtab_placement,
        .phtab_adjustment           = phtab_adjustment,
        .file_size                  = file_size,
        .original_segment_count     = original_count,
        .new_segment_count          = new_count,
        .payload_size               = request->payload_size,
        .p_memsz                    = request->p_memsz,
        .effective_file_alignment   = file_alignment,
        .effective_vaddr_alignment  = vaddr_alignment,
        .segment_flags              = request->segment_flags,
        .policy                     = request->policy,
        .entrypoint_policy_deferred = true,
    };
}

static n00b_result_t(n00b_elf_rewrite_admit_loadable_result_t)
accepted_loadable(n00b_elf_binary_t                         *bin,
                  n00b_elf_rewrite_admit_loadable_request_t *request,
                  uint64_t                                   file_alignment,
                  uint64_t                                   vaddr_alignment,
                  n00b_elf_rewrite_loadable_phtab_adjustment_t phtab_adjustment)
{
    n00b_elf_rewrite_admit_loadable_result_t result =
        make_loadable_result(bin,
                             request,
                             file_alignment,
                             vaddr_alignment,
                             N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED,
                             N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
                             phtab_adjustment);

    return n00b_result_ok(n00b_elf_rewrite_admit_loadable_result_t, result);
}

static n00b_result_t(n00b_elf_rewrite_admit_loadable_result_t)
rejected_loadable(n00b_elf_binary_t                         *bin,
                  n00b_elf_rewrite_admit_loadable_request_t *request,
                  uint64_t                                   file_alignment,
                  uint64_t                                   vaddr_alignment,
                  n00b_elf_rewrite_admit_rejection_reason_t  reason,
                  n00b_elf_rewrite_loadable_phtab_adjustment_t phtab_adjustment)
{
    n00b_elf_rewrite_admit_loadable_result_t result =
        make_loadable_result(bin,
                             request,
                             file_alignment,
                             vaddr_alignment,
                             N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED,
                             reason,
                             phtab_adjustment);

    return n00b_result_ok(n00b_elf_rewrite_admit_loadable_result_t, result);
}

static n00b_elf_rewrite_admit_rejection_reason_t
check_loadable_phtab_form(n00b_elf_binary_t *bin)
{
    if (bin->header.phnum == N00B_ELF_PN_XNUM) {
        return N00B_ELF_REWRITE_ADMIT_REJECT_UNSUPPORTED_PN_XNUM;
    }

    if (bin->header.phnum + 1 >= N00B_ELF_PN_XNUM) {
        return N00B_ELF_REWRITE_ADMIT_REJECT_UNSUPPORTED_PN_XNUM;
    }

    if (bin->header.phnum == 0
        || bin->header.phentsize != N00B_ELF64_PHDR_SIZE
        || bin->header.phoff == 0) {
        return N00B_ELF_REWRITE_ADMIT_REJECT_INVALID_PHTAB;
    }

    uint64_t phtab_size;
    if (!checked_mul_u64(bin->header.phnum,
                         N00B_ELF64_PHDR_SIZE,
                         &phtab_size)) {
        return N00B_ELF_REWRITE_ADMIT_REJECT_INVALID_PHTAB;
    }

    uint64_t file_size = 0;
    if (bin->stream != nullptr && bin->stream->buf != nullptr) {
        file_size = bin->stream->buf->byte_len;
    }

    if (!validate_packager_bounds(phtab_size, bin->header.phoff, file_size)) {
        return N00B_ELF_REWRITE_ADMIT_REJECT_INVALID_PHTAB;
    }

    return N00B_ELF_REWRITE_ADMIT_REJECT_NONE;
}

static n00b_result_t(n00b_elf_rewrite_loadable_phtab_adjustment_t)
analyze_in_place_phtab_adjustment(n00b_elf_binary_t *bin,
                                  n00b_elf_layout_t *layout,
                                  n00b_allocator_t  *allocator)
{
    n00b_elf_rewrite_loadable_phtab_adjustment_t facts =
        no_phtab_adjustment();

    if (bin->header.phnum + 1 >= N00B_ELF_PN_XNUM) {
        return n00b_result_ok(
            n00b_elf_rewrite_loadable_phtab_adjustment_t,
            rejected_phtab_adjustment(
                N00B_ELF_REWRITE_ADMIT_REJECT_UNSUPPORTED_PN_XNUM,
                N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_HARD));
    }

    uint64_t phtab_size;
    uint64_t phtab_end;
    uint64_t adjusted_phtab_size;
    if (!checked_mul_u64(bin->header.phnum,
                         N00B_ELF64_PHDR_SIZE,
                         &phtab_size)
        || !checked_add_u64(bin->header.phoff, phtab_size, &phtab_end)
        || !checked_add_u64(phtab_size,
                            N00B_ELF64_PHDR_SIZE,
                            &adjusted_phtab_size)) {
        return n00b_result_err(n00b_elf_rewrite_loadable_phtab_adjustment_t,
                               N00B_ELF_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    facts.original_phtab_offset = bin->header.phoff;
    facts.original_phtab_size   = phtab_size;
    facts.adjusted_phtab_size   = adjusted_phtab_size;

    n00b_elf_segment_t *containing_load = nullptr;
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_elf_segment_t *seg = &bin->segments[i];

        if (seg->type != PT_LOAD || bin->header.phoff < seg->offset) {
            continue;
        }

        uint64_t seg_file_end;
        if (!checked_add_u64(seg->offset, seg->filesz, &seg_file_end)) {
            return n00b_result_err(
                n00b_elf_rewrite_loadable_phtab_adjustment_t,
                N00B_ELF_REWRITE_ADMIT_ERR_OVERFLOW);
        }

        if (phtab_end <= seg_file_end) {
            containing_load = seg;
            facts.containing_load_index = i;
            facts.containing_load_file_end = seg_file_end;
            break;
        }
    }

    if (containing_load == nullptr) {
        facts.status = N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_HARD;
        facts.rejection_reason =
            N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_OUTSIDE_LOAD;
        return n00b_result_ok(n00b_elf_rewrite_loadable_phtab_adjustment_t,
                              facts);
    }

    uint64_t phtab_vaddr;
    if (!checked_add_u64(containing_load->vaddr,
                         bin->header.phoff - containing_load->offset,
                         &phtab_vaddr)
        || !checked_add_u64(containing_load->vaddr,
                            containing_load->memsz,
                            &facts.containing_load_memory_end)) {
        return n00b_result_err(n00b_elf_rewrite_loadable_phtab_adjustment_t,
                               N00B_ELF_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_elf_segment_t *seg = &bin->segments[i];

        if (seg->type != PT_PHDR) {
            continue;
        }

        if (facts.pt_phdr_present || seg->offset != bin->header.phoff
            || seg->filesz != phtab_size || seg->memsz != phtab_size
            || seg->vaddr != phtab_vaddr) {
            facts.status = N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_HARD;
            facts.rejection_reason =
                N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_INCONSISTENT;
            return n00b_result_ok(
                n00b_elf_rewrite_loadable_phtab_adjustment_t,
                facts);
        }

        facts.pt_phdr_present = true;
        facts.pt_phdr_index   = i;
    }

    if (!facts.pt_phdr_present) {
        facts.status = N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_HARD;
        facts.rejection_reason =
            N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_MISSING;
        return n00b_result_ok(n00b_elf_rewrite_loadable_phtab_adjustment_t,
                              facts);
    }

    uint64_t memory_padding = pad8(facts.containing_load_memory_end);
    uint64_t memory_search_end;
    if (!checked_add_u64(facts.containing_load_memory_end,
                         memory_padding,
                         &facts.adjusted_phtab_vaddr)
        || !checked_add_u64(facts.adjusted_phtab_vaddr,
                            adjusted_phtab_size,
                            &memory_search_end)) {
        return n00b_result_err(n00b_elf_rewrite_loadable_phtab_adjustment_t,
                               N00B_ELF_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    auto memory_collision =
        n00b_elf_layout_page_load_vaddr_collision(
            bin,
            facts.containing_load_memory_end,
            memory_search_end,
            N00B_ELF_LOAD_PAGE_SIZE,
            .allocator = allocator);
    if (n00b_result_is_err(memory_collision)) {
        return n00b_result_err(
            n00b_elf_rewrite_loadable_phtab_adjustment_t,
            layout_err_to_admit_err(n00b_result_get_err(memory_collision)));
    }

    if (n00b_result_get(memory_collision).interval_count != 0) {
        facts.status =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_RELOCATABLE;
        facts.rejection_reason =
            N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_MEMORY_COLLISION;
        return n00b_result_ok(n00b_elf_rewrite_loadable_phtab_adjustment_t,
                              facts);
    }

    uint64_t raw_adjusted_offset;
    uint64_t file_search_end;
    /* Match Brandon: preserve any BSS expectation by placing the adjusted
     * PHTAB after p_memsz while checking zero file slack starting at p_filesz.
     */
    if (!checked_add_u64(containing_load->offset,
                         containing_load->memsz,
                         &raw_adjusted_offset)
        || !checked_add_u64(raw_adjusted_offset,
                            pad8(raw_adjusted_offset),
                            &facts.adjusted_phtab_offset)
        || !checked_add_u64(facts.adjusted_phtab_offset,
                            adjusted_phtab_size,
                            &file_search_end)) {
        return n00b_result_err(n00b_elf_rewrite_loadable_phtab_adjustment_t,
                               N00B_ELF_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    auto file_collision =
        n00b_elf_layout_file_collision(layout,
                                       facts.containing_load_file_end,
                                       file_search_end,
                                       .allocator = allocator);
    if (n00b_result_is_err(file_collision)) {
        return n00b_result_err(
            n00b_elf_rewrite_loadable_phtab_adjustment_t,
            layout_err_to_admit_err(n00b_result_get_err(file_collision)));
    }

    n00b_elf_layout_collision_t file_collision_facts =
        n00b_result_get(file_collision);
    if (phtab_adjust_collision_has_modeled_elf_object(
            &file_collision_facts)) {
        facts.status =
            N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_RELOCATABLE;
        facts.rejection_reason =
            N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_FILE_COLLISION;
        return n00b_result_ok(n00b_elf_rewrite_loadable_phtab_adjustment_t,
                              facts);
    }

    auto next_result =
        phtab_adjust_next_modeled_file_interval(
            layout,
            facts.containing_load_file_end);
    if (n00b_result_is_err(next_result)) {
        return n00b_result_err(
            n00b_elf_rewrite_loadable_phtab_adjustment_t,
            layout_err_to_admit_err(n00b_result_get_err(next_result)));
    }

    n00b_option_t(n00b_elf_layout_interval_t) next_opt =
        n00b_result_get(next_result);
    if (!n00b_option_is_set(next_opt)) {
        facts.status = N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_HARD;
        facts.rejection_reason =
            facts.containing_load_file_end == layout->file_size
                ? N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_AT_EOF
                : N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_EXTRA_DATA_BEFORE_EOF;
        return n00b_result_ok(n00b_elf_rewrite_loadable_phtab_adjustment_t,
                              facts);
    }

    n00b_elf_layout_interval_t next = n00b_option_get(next_opt);
    facts.next_file_object_offset = next.start;
    facts.zero_slack_start        = facts.containing_load_file_end;
    facts.zero_slack_end          = next.start;

    if (next.start > facts.containing_load_file_end) {
        auto gap_result =
            n00b_elf_layout_find_file_gap(layout,
                                          facts.containing_load_file_end,
                                          next.start,
                                          next.start
                                              - facts.containing_load_file_end,
                                          1);
        if (n00b_result_is_err(gap_result)) {
            return n00b_result_err(
                n00b_elf_rewrite_loadable_phtab_adjustment_t,
                layout_err_to_admit_err(n00b_result_get_err(gap_result)));
        }

        n00b_option_t(n00b_elf_layout_gap_t) gap_opt =
            n00b_result_get(gap_result);
        if (!n00b_option_is_set(gap_opt)
            || n00b_option_get(gap_opt).kind
                   != N00B_ELF_LAYOUT_GAP_ZERO_PADDING
            || n00b_option_get(gap_opt).start
                   != facts.containing_load_file_end
            || n00b_option_get(gap_opt).end < next.start) {
            facts.status =
                N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_RELOCATABLE;
            facts.rejection_reason =
                N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_NONZERO_SLACK;
            return n00b_result_ok(
                n00b_elf_rewrite_loadable_phtab_adjustment_t,
                facts);
        }
    }

    facts.status                  =
        N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_ACCEPTED;
    facts.rejection_reason        = N00B_ELF_REWRITE_ADMIT_REJECT_NONE;
    facts.required_file_extension =
        file_search_end - facts.containing_load_file_end;
    facts.required_memory_extension =
        memory_search_end - facts.containing_load_memory_end;
    facts.pt_phdr_new_offset = facts.adjusted_phtab_offset;
    facts.pt_phdr_new_filesz = facts.adjusted_phtab_size;
    facts.pt_phdr_new_memsz  = facts.adjusted_phtab_size;
    facts.pt_phdr_new_vaddr  = facts.adjusted_phtab_vaddr;

    return n00b_result_ok(n00b_elf_rewrite_loadable_phtab_adjustment_t,
                          facts);
}

n00b_result_t(n00b_elf_rewrite_admit_loadable_result_t)
n00b_elf_rewrite_admit_loadable_insert(
    n00b_elf_binary_t                         *bin,
    n00b_elf_rewrite_admit_loadable_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (bin == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_admit_loadable_result_t,
                               N00B_ELF_REWRITE_ADMIT_ERR_NULL_BINARY);
    }

    if (request == nullptr) {
        return n00b_result_err(n00b_elf_rewrite_admit_loadable_result_t,
                               N00B_ELF_REWRITE_ADMIT_ERR_NULL_REQUEST);
    }

    if (request->payload_size == 0) {
        return n00b_result_err(n00b_elf_rewrite_admit_loadable_result_t,
                               N00B_ELF_REWRITE_ADMIT_ERR_ZERO_PAYLOAD_SIZE);
    }

    uint64_t file_alignment  = effective_alignment(request->file_alignment);
    uint64_t vaddr_alignment = effective_alignment(request->vaddr_alignment);

    if (request->p_memsz < request->payload_size) {
        return rejected_loadable(bin,
                                 request,
                                 file_alignment,
                                 vaddr_alignment,
                                 N00B_ELF_REWRITE_ADMIT_REJECT_PAYLOAD_MEMSZ,
                                 no_phtab_adjustment());
    }

    if ((request->segment_flags & ~(uint32_t)(PF_R | PF_W | PF_X)) != 0
        || request->phtab_strategy
               == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_NONE) {
        return rejected_loadable(
            bin,
            request,
            file_alignment,
            vaddr_alignment,
            N00B_ELF_REWRITE_ADMIT_REJECT_INVALID_LOADABLE_REQUEST,
            no_phtab_adjustment());
    }

    if (target_has_reserved_section(bin)) {
        return rejected_loadable(bin,
                                 request,
                                 file_alignment,
                                 vaddr_alignment,
                                 N00B_ELF_REWRITE_ADMIT_REJECT_RESERVED_TARGET,
                                 no_phtab_adjustment());
    }

    if (request->phtab_strategy
        == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST
        && bin->header.phnum + 1 >= N00B_ELF_PN_XNUM) {
        n00b_elf_rewrite_loadable_phtab_adjustment_t phtab_adjustment =
            rejected_phtab_adjustment(
                N00B_ELF_REWRITE_ADMIT_REJECT_UNSUPPORTED_PN_XNUM,
                N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_HARD);
        return rejected_loadable(bin,
                                 request,
                                 file_alignment,
                                 vaddr_alignment,
                                 N00B_ELF_REWRITE_ADMIT_REJECT_UNSUPPORTED_PN_XNUM,
                                 phtab_adjustment);
    }

    n00b_elf_rewrite_admit_rejection_reason_t phtab_reason =
        check_loadable_phtab_form(bin);
    if (phtab_reason != N00B_ELF_REWRITE_ADMIT_REJECT_NONE) {
        return rejected_loadable(bin,
                                 request,
                                 file_alignment,
                                 vaddr_alignment,
                                 phtab_reason,
                                 no_phtab_adjustment());
    }

    auto layout_result = n00b_elf_layout_build(bin, .allocator = allocator);
    if (n00b_result_is_err(layout_result)) {
        return n00b_result_err(
            n00b_elf_rewrite_admit_loadable_result_t,
            layout_err_to_admit_err(n00b_result_get_err(layout_result)));
    }
    n00b_elf_layout_t *layout = n00b_result_get(layout_result);

    n00b_elf_rewrite_loadable_phtab_adjustment_t phtab_adjustment =
        no_phtab_adjustment();
    if (request->phtab_strategy
        == N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST) {
        auto adjustment_result =
            analyze_in_place_phtab_adjustment(bin, layout, allocator);
        if (n00b_result_is_err(adjustment_result)) {
            return n00b_result_err(
                n00b_elf_rewrite_admit_loadable_result_t,
                n00b_result_get_err(adjustment_result));
        }

        phtab_adjustment = n00b_result_get(adjustment_result);
        if (phtab_adjustment.status
            != N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_ACCEPTED) {
            if (phtab_adjustment.status
                == N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_NONE) {
                phtab_adjustment =
                    rejected_phtab_adjustment(
                        phtab_adjustment.rejection_reason,
                        rejection_is_hard_for_in_place_phtab(
                            phtab_adjustment.rejection_reason)
                            ? N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_HARD
                            : N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_RELOCATABLE);
            }

            return rejected_loadable(bin,
                                     request,
                                     file_alignment,
                                     vaddr_alignment,
                                     phtab_adjustment.rejection_reason,
                                     phtab_adjustment);
        }
    }

    if (policy_has(request->policy,
                   N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION)) {
        auto loader_reason = check_loader_preservation(bin);
        if (n00b_result_is_err(loader_reason)) {
            return n00b_result_err(n00b_elf_rewrite_admit_loadable_result_t,
                                   n00b_result_get_err(loader_reason));
        }

        n00b_elf_rewrite_admit_rejection_reason_t reason =
            n00b_result_get(loader_reason);
        if (reason != N00B_ELF_REWRITE_ADMIT_REJECT_NONE) {
            return rejected_loadable(bin,
                                     request,
                                     file_alignment,
                                     vaddr_alignment,
                                     reason,
                                     phtab_adjustment);
        }
    }

    return accepted_loadable(bin,
                             request,
                             file_alignment,
                             vaddr_alignment,
                             phtab_adjustment);
}

n00b_result_t(n00b_elf_rewrite_admit_result_t)
n00b_elf_rewrite_admit_metadata_insert(
    n00b_elf_binary_t                         *bin,
    n00b_elf_rewrite_admit_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return admit_metadata_insert_impl(bin,
                                      request,
                                      TRUSTED_METADATA_NONE,
                                      allocator);
}

n00b_result_t(n00b_elf_rewrite_admit_result_t)
n00b_elf_rewrite_admit_chalk_mark_insert(
    n00b_elf_binary_t                         *bin,
    n00b_elf_rewrite_admit_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return admit_metadata_insert_impl(bin,
                                      request,
                                      TRUSTED_METADATA_CHALK_MARK,
                                      allocator);
}

n00b_result_t(n00b_elf_rewrite_admit_result_t)
n00b_elf_rewrite_admit_object_bundle_insert(
    n00b_elf_binary_t                         *bin,
    n00b_elf_rewrite_admit_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    return admit_metadata_insert_impl(bin,
                                      request,
                                      TRUSTED_METADATA_OBJECT_BUNDLE,
                                      allocator);
}

n00b_string_t *
n00b_elf_rewrite_admit_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_ELF_REWRITE_ADMIT_ERR_NULL_BINARY:
        return r"ELF rewrite admission: null binary";
    case N00B_ELF_REWRITE_ADMIT_ERR_NULL_REQUEST:
        return r"ELF rewrite admission: null request";
    case N00B_ELF_REWRITE_ADMIT_ERR_NULL_SECTION_NAME:
        return r"ELF rewrite admission: null section name";
    case N00B_ELF_REWRITE_ADMIT_ERR_ZERO_PAYLOAD_SIZE:
        return r"ELF rewrite admission: zero payload size";
    case N00B_ELF_REWRITE_ADMIT_ERR_LAYOUT_SUBSTRATE:
        return r"ELF rewrite admission: layout substrate failure";
    case N00B_ELF_REWRITE_ADMIT_ERR_OVERFLOW:
        return r"ELF rewrite admission: arithmetic overflow";
    default:
        return r"ELF rewrite admission: unknown error code";
    }
}

n00b_string_t *
n00b_elf_rewrite_admit_policy_flag_str(
    n00b_elf_rewrite_admit_policy_flag_t flag)
{
    switch (flag) {
    case N00B_ELF_REWRITE_ADMIT_POLICY_NONE:
        return r"none";
    case N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION:
        return r"strict-loader-preservation";
    case N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY:
        return r"preserve-overlay";
    case N00B_ELF_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY:
        return r"append-after-overlay";
    default:
        return r"unknown-elf-rewrite-admit-policy-flag";
    }
}

n00b_string_t *
n00b_elf_rewrite_admit_outcome_str(
    n00b_elf_rewrite_admit_outcome_t outcome)
{
    switch (outcome) {
    case N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED:
        return r"accepted";
    case N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED:
        return r"rejected";
    default:
        return r"unknown-elf-rewrite-admit-outcome";
    }
}

n00b_string_t *
n00b_elf_rewrite_admit_placement_kind_str(
    n00b_elf_rewrite_admit_placement_kind_t kind)
{
    switch (kind) {
    case N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE:
        return r"none";
    case N00B_ELF_REWRITE_ADMIT_PLACEMENT_EOF_TAIL:
        return r"eof-tail";
    case N00B_ELF_REWRITE_ADMIT_PLACEMENT_FILE_GAP:
        return r"file-gap";
    case N00B_ELF_REWRITE_ADMIT_PLACEMENT_AFTER_OVERLAY:
        return r"after-overlay";
    default:
        return r"unknown-elf-rewrite-admit-placement-kind";
    }
}

n00b_string_t *
n00b_elf_rewrite_admit_rejection_reason_str(
    n00b_elf_rewrite_admit_rejection_reason_t reason)
{
    switch (reason) {
    case N00B_ELF_REWRITE_ADMIT_REJECT_NONE:
        return r"none";
    case N00B_ELF_REWRITE_ADMIT_REJECT_NOT_YET_CHECKED:
        return r"not-yet-checked";
    case N00B_ELF_REWRITE_ADMIT_REJECT_RESERVED_SECTION_NAME:
        return r"reserved-section-name";
    case N00B_ELF_REWRITE_ADMIT_REJECT_SECTION_NOT_METADATA:
        return r"section-not-metadata";
    case N00B_ELF_REWRITE_ADMIT_REJECT_NO_SAFE_PLACEMENT:
        return r"no-safe-placement";
    case N00B_ELF_REWRITE_ADMIT_REJECT_FILE_COLLISION:
        return r"file-collision";
    case N00B_ELF_REWRITE_ADMIT_REJECT_UNKNOWN_NONZERO_BYTES:
        return r"unknown-nonzero-bytes";
    case N00B_ELF_REWRITE_ADMIT_REJECT_OVERLAY_POLICY:
        return r"overlay-policy";
    case N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_OUTSIDE_LOAD:
        return r"phtab-outside-load";
    case N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_MISSING:
        return r"pt-phdr-missing";
    case N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_INCONSISTENT:
        return r"pt-phdr-inconsistent";
    case N00B_ELF_REWRITE_ADMIT_REJECT_ENTRY_OUTSIDE_LOAD:
        return r"entry-outside-load";
    case N00B_ELF_REWRITE_ADMIT_REJECT_ENTRY_MEMORY_ONLY:
        return r"entry-memory-only";
    case N00B_ELF_REWRITE_ADMIT_REJECT_LOADER_PRESERVATION:
        return r"loader-preservation";
    case N00B_ELF_REWRITE_ADMIT_REJECT_INVALID_LOADABLE_REQUEST:
        return r"invalid-loadable-request";
    case N00B_ELF_REWRITE_ADMIT_REJECT_PAYLOAD_MEMSZ:
        return r"payload-memsz";
    case N00B_ELF_REWRITE_ADMIT_REJECT_INVALID_PHTAB:
        return r"invalid-phtab";
    case N00B_ELF_REWRITE_ADMIT_REJECT_UNSUPPORTED_PN_XNUM:
        return r"unsupported-pn-xnum";
    case N00B_ELF_REWRITE_ADMIT_REJECT_RESERVED_TARGET:
        return r"reserved-target";
    case N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_MEMORY_COLLISION:
        return r"phtab-adjust-memory-collision";
    case N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_FILE_COLLISION:
        return r"phtab-adjust-file-collision";
    case N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_NONZERO_SLACK:
        return r"phtab-adjust-nonzero-slack";
    case N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_AT_EOF:
        return r"phtab-adjust-at-eof";
    case N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_EXTRA_DATA_BEFORE_EOF:
        return r"phtab-adjust-extra-data-before-eof";
    default:
        return r"unknown-elf-rewrite-admit-rejection-reason";
    }
}

n00b_string_t *
n00b_elf_rewrite_loadable_phtab_strategy_str(
    n00b_elf_rewrite_loadable_phtab_strategy_t strategy)
{
    switch (strategy) {
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_NONE:
        return r"none";
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_DEFERRED:
        return r"deferred";
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST:
        return r"in-place-adjust";
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE:
        return r"relocate";
    default:
        return r"unknown-elf-rewrite-loadable-phtab-strategy";
    }
}

n00b_string_t *
n00b_elf_rewrite_loadable_placement_kind_str(
    n00b_elf_rewrite_loadable_placement_kind_t kind)
{
    switch (kind) {
    case N00B_ELF_REWRITE_LOADABLE_PLACEMENT_NONE:
        return r"none";
    case N00B_ELF_REWRITE_LOADABLE_PLACEMENT_DEFERRED:
        return r"deferred";
    case N00B_ELF_REWRITE_LOADABLE_PLACEMENT_IN_PLACE_PHTAB:
        return r"in-place-phtab";
    case N00B_ELF_REWRITE_LOADABLE_PLACEMENT_RELOCATED_PHTAB:
        return r"relocated-phtab";
    case N00B_ELF_REWRITE_LOADABLE_PLACEMENT_LOADABLE_PAYLOAD:
        return r"loadable-payload";
    default:
        return r"unknown-elf-rewrite-loadable-placement-kind";
    }
}

n00b_string_t *
n00b_elf_rewrite_loadable_phtab_adjust_status_str(
    n00b_elf_rewrite_loadable_phtab_adjust_status_t status)
{
    switch (status) {
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_NONE:
        return r"none";
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_ACCEPTED:
        return r"accepted";
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_RELOCATABLE:
        return r"rejected-relocatable";
    case N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_HARD:
        return r"rejected-hard";
    default:
        return r"unknown-elf-rewrite-loadable-phtab-adjust-status";
    }
}
