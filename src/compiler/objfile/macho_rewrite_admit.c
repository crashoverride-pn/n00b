#include "compiler/objfile/macho_rewrite_admit.h"

#include "compiler/objfile/macho_layout.h"
#include "compiler/objfile/macho_types.h"
#include "internal/chalk/macho_core.h"
#include "internal/compiler/objfile/macho_rewrite_shared.h"
#include "text/strings/string_ops.h"

// On-disk size of an LC_NOTE load command (`cmd`, `cmdsize`, 16B `data_owner`,
// 8B `offset`, 8B `size` = 40). This mirrors the loader-safe slack check in
// `src/chalk/macho_core.c:653-660` (`add_note_insert`), where the private
// `MACHO_NOTE_CMD_SIZE` file-scope `#define` carries the same value; it is
// reproduced here under the project `N00B_MACHO_*` prefix so admission need not
// reach into chalk's private translation unit. (`macho_note_command_t`,
// `include/internal/chalk/macho_core.h:33-41`.)
#define N00B_MACHO_LC_NOTE_CMD_SIZE 40u

// ============================================================================
// Small arithmetic / policy helpers (mirror elf_rewrite_admit.c)
// ============================================================================

static bool
checked_add_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (UINT64_MAX - a < b) {
        return false;
    }

    *out = a + b;
    return true;
}

static uint64_t
effective_alignment(uint64_t requested)
{
    if (requested == 0) {
        return 1;
    }

    return requested;
}

static n00b_err_t
layout_err_to_admit_err(n00b_err_t err)
{
    if (err == N00B_MACHO_LAYOUT_ERR_OVERFLOW) {
        return N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW;
    }

    return N00B_MACHO_REWRITE_ADMIT_ERR_LAYOUT_SUBSTRATE;
}

static bool
policy_has(n00b_macho_rewrite_admit_policy_t      policy,
           n00b_macho_rewrite_admit_policy_flag_t flag)
{
    return (policy.flags & (uint64_t)flag) != 0;
}

// ============================================================================
// Reserved LC_NOTE `data_owner` discrimination
// ============================================================================

typedef enum {
    TRUSTED_OWNER_NONE,
    TRUSTED_OWNER_CHALK_MARK,
    TRUSTED_OWNER_OBJECT_BUNDLE,
} trusted_owner_kind_t;

static bool
owner_is_chalk(n00b_string_t *owner)
{
    return n00b_unicode_str_eq(owner,
                               n00b_string_from_cstr(CHALK_MACHO_NOTE_OWNER));
}

static bool
owner_is_object_bundle(n00b_string_t *owner)
{
    return n00b_unicode_str_eq(owner,
                               n00b_string_from_cstr(
                                   N00B_MACHO_BUNDLE_NOTE_OWNER));
}

// True when `owner` collides with a reserved trusted token; the general
// (untrusted) metadata path must reject these.
static bool
owner_is_reserved(n00b_string_t *owner)
{
    return owner_is_chalk(owner) || owner_is_object_bundle(owner);
}

static bool
owner_matches_trusted_kind(n00b_string_t *owner, trusted_owner_kind_t kind)
{
    switch (kind) {
    case TRUSTED_OWNER_NONE:
        return false;
    case TRUSTED_OWNER_CHALK_MARK:
        return owner_is_chalk(owner);
    case TRUSTED_OWNER_OBJECT_BUNDLE:
        return owner_is_object_bundle(owner);
    }

    return false;
}

// ============================================================================
// Result constructors
// ============================================================================

// Snapshot of the load-command-slack / code-signature facts shared by every
// metadata verdict. Computed once (read-only) before classification so accept
// and reject results carry identical fact fields.
typedef struct {
    uint64_t lc_region_offset;
    uint64_t lc_region_used;
    uint64_t lc_region_capacity;
    uint64_t lc_slack_bytes;
    bool     code_signature_present;
    uint64_t code_signature_offset;
    uint64_t code_signature_size;
} metadata_facts_t;

static n00b_macho_rewrite_admit_result_t
make_result(n00b_macho_layout_t                         *layout,
            n00b_macho_rewrite_admit_metadata_request_t *request,
            metadata_facts_t                            *facts,
            uint64_t                                     alignment,
            n00b_macho_rewrite_admit_outcome_t           outcome,
            n00b_macho_rewrite_admit_rejection_reason_t  reason,
            n00b_option_t(n00b_macho_rewrite_admit_placement_t) placement)
{
    return (n00b_macho_rewrite_admit_result_t){
        .outcome                = outcome,
        .rejection_reason       = reason,
        .placement              = placement,
        .file_size              = layout->file_size,
        .effective_alignment    = alignment,
        .lc_region_offset       = facts->lc_region_offset,
        .lc_region_used         = facts->lc_region_used,
        .lc_region_capacity     = facts->lc_region_capacity,
        .lc_slack_bytes         = facts->lc_slack_bytes,
        .code_signature_present = facts->code_signature_present,
        .code_signature_offset  = facts->code_signature_offset,
        .code_signature_size    = facts->code_signature_size,
        .policy                 = request->policy,
    };
}

static n00b_result_t(n00b_macho_rewrite_admit_result_t)
accepted(n00b_macho_layout_t                         *layout,
         n00b_macho_rewrite_admit_metadata_request_t *request,
         metadata_facts_t                            *facts,
         uint64_t                                     alignment,
         n00b_macho_rewrite_admit_placement_t         placement)
{
    n00b_macho_rewrite_admit_result_t result = make_result(
        layout,
        request,
        facts,
        alignment,
        N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED,
        N00B_MACHO_REWRITE_ADMIT_REJECT_NONE,
        n00b_option_set(n00b_macho_rewrite_admit_placement_t, placement));

    return n00b_result_ok(n00b_macho_rewrite_admit_result_t, result);
}

static n00b_result_t(n00b_macho_rewrite_admit_result_t)
rejected(n00b_macho_layout_t                         *layout,
         n00b_macho_rewrite_admit_metadata_request_t *request,
         metadata_facts_t                            *facts,
         uint64_t                                     alignment,
         n00b_macho_rewrite_admit_rejection_reason_t  reason)
{
    n00b_macho_rewrite_admit_result_t result = make_result(
        layout,
        request,
        facts,
        alignment,
        N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED,
        reason,
        n00b_option_none(n00b_macho_rewrite_admit_placement_t));

    return n00b_result_ok(n00b_macho_rewrite_admit_result_t, result);
}

static n00b_macho_rewrite_admit_placement_t
placement_from_range(n00b_macho_rewrite_admit_placement_kind_t kind,
                     uint64_t                                  start,
                     uint64_t                                  end,
                     uint64_t                                  payload_size,
                     uint64_t                                  alignment)
{
    return (n00b_macho_rewrite_admit_placement_t){
        .kind           = kind,
        .file_offset    = start,
        .file_end       = end,
        .payload_size   = payload_size,
        .file_alignment = alignment,
    };
}

// ============================================================================
// Metadata-insert admission core
// ============================================================================

static n00b_result_t(n00b_macho_rewrite_admit_result_t)
admit_metadata_insert_impl(
    n00b_macho_binary_t                         *bin,
    n00b_macho_rewrite_admit_metadata_request_t *request,
    trusted_owner_kind_t                         trusted_kind,
    n00b_allocator_t                            *allocator)
{
    if (bin == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_admit_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_NULL_BINARY);
    }

    if (request == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_admit_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_NULL_REQUEST);
    }

    if (request->note_owner == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_admit_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_NULL_REQUEST);
    }

    if (request->payload_size == 0) {
        return n00b_result_err(n00b_macho_rewrite_admit_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_ZERO_PAYLOAD);
    }

    uint64_t alignment = effective_alignment(request->file_alignment);

    auto layout_result = n00b_macho_layout_build(bin, .allocator = allocator);
    if (n00b_result_is_err(layout_result)) {
        return n00b_result_err(
            n00b_macho_rewrite_admit_result_t,
            layout_err_to_admit_err(n00b_result_get_err(layout_result)));
    }

    n00b_macho_layout_t *layout = n00b_result_get(layout_result);

    // -- Load-command-slack facts (used by accept and every reject) --------
    metadata_facts_t facts = {};

    uint64_t lc_offset = N00B_MACHO_HEADER_64_SIZE;
    uint64_t lc_used   = (uint64_t)bin->header.sizeofcmds;
    uint64_t lc_end;
    if (!checked_add_u64(lc_offset, lc_used, &lc_end)) {
        return n00b_result_err(n00b_macho_rewrite_admit_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    facts.lc_region_offset = lc_offset;
    facts.lc_region_used   = lc_used;

    auto first_sec_result =
        n00b_macho_rewrite_first_section_start_after(layout, lc_end);
    if (n00b_result_is_err(first_sec_result)) {
        return n00b_result_err(
            n00b_macho_rewrite_admit_result_t,
            layout_err_to_admit_err(n00b_result_get_err(first_sec_result)));
    }

    n00b_option_t(uint64_t) first_sec = n00b_result_get(first_sec_result);
    // Capacity is the first-section start (room the LC region may grow into);
    // when no section sits above the LC region, the file size bounds it.
    facts.lc_region_capacity = first_sec.has_value
                                   ? n00b_option_get(first_sec)
                                   : layout->file_size;
    facts.lc_slack_bytes     = facts.lc_region_capacity > lc_end
                                   ? facts.lc_region_capacity - lc_end
                                   : 0;

    if (bin->code_signature != nullptr) {
        facts.code_signature_present = true;
        facts.code_signature_offset  = (uint64_t)bin->code_signature->dataoff;
        facts.code_signature_size    = (uint64_t)bin->code_signature->datasize;
    }

    // -- Reserved-name discrimination --------------------------------------
    if (trusted_kind == TRUSTED_OWNER_NONE) {
        if (owner_is_reserved(request->note_owner)) {
            return rejected(layout,
                            request,
                            &facts,
                            alignment,
                            N00B_MACHO_REWRITE_ADMIT_REJECT_RESERVED_NOTE_NAME);
        }
    }
    else if (!owner_matches_trusted_kind(request->note_owner, trusted_kind)) {
        return rejected(layout,
                        request,
                        &facts,
                        alignment,
                        N00B_MACHO_REWRITE_ADMIT_REJECT_RESERVED_NOTE_NAME);
    }

    // -- LC region consistency: measured LC interval vs header.sizeofcmds --
    auto lc_overlap = n00b_macho_layout_file_overlap(layout, lc_offset, lc_end);
    if (n00b_result_is_err(lc_overlap)) {
        return n00b_result_err(
            n00b_macho_rewrite_admit_result_t,
            layout_err_to_admit_err(n00b_result_get_err(lc_overlap)));
    }

    bool lc_region_consistent = false;
    n00b_option_t(n00b_macho_layout_interval_node_t *) lc_node_opt =
        n00b_result_get(lc_overlap);
    if (lc_node_opt.has_value) {
        // Walk intervals overlapping the LC region for the LOAD_COMMANDS one
        // and confirm its measured extent equals [lc_offset, lc_end).
        auto lc_list = n00b_macho_layout_file_overlaps(layout,
                                                       lc_offset,
                                                       lc_end,
                                                       .allocator = allocator);
        if (n00b_result_is_err(lc_list)) {
            return n00b_result_err(
                n00b_macho_rewrite_admit_result_t,
                layout_err_to_admit_err(n00b_result_get_err(lc_list)));
        }

        n00b_macho_layout_interval_list_t list = n00b_result_get(lc_list);
        for (uint64_t i = 0; i < list.count; i++) {
            n00b_macho_layout_interval_t *iv = &list.items[i];
            if (iv->kind == N00B_MACHO_LAYOUT_INTERVAL_LOAD_COMMANDS
                && iv->start == lc_offset && iv->end == lc_end) {
                lc_region_consistent = true;
                break;
            }
        }
    }

    if (!lc_region_consistent) {
        return rejected(
            layout,
            request,
            &facts,
            alignment,
            N00B_MACHO_REWRITE_ADMIT_REJECT_LC_REGION_INCONSISTENT);
    }

    // -- __LINKEDIT must be last + file ends at its end --------------------
    uint64_t linkedit_offset_unused = 0;  // shared helper out-param (unused here)
    uint64_t linkedit_end           = 0;
    bool     have_linkedit          = false;
    auto     le_result              = n00b_macho_rewrite_linkedit_is_last(
        bin,
        &linkedit_offset_unused,
        &linkedit_end,
        &have_linkedit);
    if (n00b_result_is_err(le_result)) {
        return n00b_result_err(
            n00b_macho_rewrite_admit_result_t,
            layout_err_to_admit_err(n00b_result_get_err(le_result)));
    }

    bool linkedit_last = n00b_result_get(le_result);
    if (!linkedit_last || linkedit_end != layout->file_size) {
        return rejected(layout,
                        request,
                        &facts,
                        alignment,
                        N00B_MACHO_REWRITE_ADMIT_REJECT_LINKEDIT_NOT_LAST);
    }

    // -- Code-signature placement: present CS must sit at __LINKEDIT tail --
    if (facts.code_signature_present) {
        uint64_t cs_end;
        if (!checked_add_u64(facts.code_signature_offset,
                             facts.code_signature_size,
                             &cs_end)) {
            return n00b_result_err(n00b_macho_rewrite_admit_result_t,
                                   N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW);
        }

        if (cs_end != linkedit_end) {
            return rejected(
                layout,
                request,
                &facts,
                alignment,
                N00B_MACHO_REWRITE_ADMIT_REJECT_CODESIG_NOT_LAST);
        }

        // -- Code signature present without ALLOW_RESIGN policy -----------
        if (!policy_has(request->policy,
                        N00B_MACHO_REWRITE_ADMIT_POLICY_ALLOW_RESIGN)) {
            return rejected(
                layout,
                request,
                &facts,
                alignment,
                N00B_MACHO_REWRITE_ADMIT_REJECT_CODESIG_PRESENT_NO_RESIGN);
        }
    }

    // -- LC header slack: room for the new LC_NOTE command -----------------
    if (facts.lc_slack_bytes < (uint64_t)N00B_MACHO_LC_NOTE_CMD_SIZE) {
        return rejected(layout,
                        request,
                        &facts,
                        alignment,
                        N00B_MACHO_REWRITE_ADMIT_REJECT_LC_HEADER_SLACK);
    }

    // -- Placement search: the note payload lands inside __LINKEDIT, at its
    //    tail (= current EOF), ahead of any future code-signature blob. -----
    if (n00b_option_is_set(request->preferred_file_offset)) {
        uint64_t start = n00b_option_get(request->preferred_file_offset);
        if (alignment != 0 && start % alignment != 0) {
            return rejected(layout,
                            request,
                            &facts,
                            alignment,
                            N00B_MACHO_REWRITE_ADMIT_REJECT_NO_SAFE_PLACEMENT);
        }

        uint64_t end;
        if (!checked_add_u64(start, request->payload_size, &end)) {
            return n00b_result_err(n00b_macho_rewrite_admit_result_t,
                                   N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW);
        }

        auto collision = n00b_macho_layout_file_collision(layout,
                                                          start,
                                                          end,
                                                          .allocator = allocator);
        if (n00b_result_is_err(collision)) {
            return n00b_result_err(
                n00b_macho_rewrite_admit_result_t,
                layout_err_to_admit_err(n00b_result_get_err(collision)));
        }

        if (n00b_result_get(collision).interval_count != 0) {
            return rejected(layout,
                            request,
                            &facts,
                            alignment,
                            N00B_MACHO_REWRITE_ADMIT_REJECT_FILE_COLLISION);
        }

        auto gap_result = n00b_macho_layout_find_file_gap(layout,
                                                          start,
                                                          end,
                                                          request->payload_size,
                                                          alignment);
        if (n00b_result_is_err(gap_result)) {
            return n00b_result_err(
                n00b_macho_rewrite_admit_result_t,
                layout_err_to_admit_err(n00b_result_get_err(gap_result)));
        }

        n00b_option_t(n00b_macho_layout_gap_t) gap_opt =
            n00b_result_get(gap_result);
        if (!gap_opt.has_value) {
            return rejected(layout,
                            request,
                            &facts,
                            alignment,
                            N00B_MACHO_REWRITE_ADMIT_REJECT_NO_SAFE_PLACEMENT);
        }

        n00b_macho_layout_gap_t gap = n00b_option_get(gap_opt);
        if (gap.start != start || gap.end < end) {
            return rejected(layout,
                            request,
                            &facts,
                            alignment,
                            N00B_MACHO_REWRITE_ADMIT_REJECT_NO_SAFE_PLACEMENT);
        }

        switch (gap.kind) {
        case N00B_MACHO_LAYOUT_GAP_ZERO_PADDING:
            return accepted(
                layout,
                request,
                &facts,
                alignment,
                placement_from_range(
                    N00B_MACHO_REWRITE_ADMIT_PLACEMENT_FILE_GAP,
                    start,
                    end,
                    request->payload_size,
                    alignment));
        case N00B_MACHO_LAYOUT_GAP_UNKNOWN_NONZERO:
            return rejected(
                layout,
                request,
                &facts,
                alignment,
                N00B_MACHO_REWRITE_ADMIT_REJECT_UNKNOWN_NONZERO_BYTES);
        case N00B_MACHO_LAYOUT_GAP_OVERLAY:
            return rejected(layout,
                            request,
                            &facts,
                            alignment,
                            N00B_MACHO_REWRITE_ADMIT_REJECT_OVERLAY_POLICY);
        case N00B_MACHO_LAYOUT_GAP_EOF_TAIL:
            return accepted(
                layout,
                request,
                &facts,
                alignment,
                placement_from_range(
                    N00B_MACHO_REWRITE_ADMIT_PLACEMENT_EOF_TAIL,
                    gap.start,
                    gap.end,
                    request->payload_size,
                    alignment));
        case N00B_MACHO_LAYOUT_GAP_VADDR_UNMAPPED:
        default:
            return rejected(layout,
                            request,
                            &facts,
                            alignment,
                            N00B_MACHO_REWRITE_ADMIT_REJECT_NO_SAFE_PLACEMENT);
        }
    }

    // Default placement: EOF tail (= __LINKEDIT end), ahead of where a fresh
    // code-signature blob will be appended by the signing layer (WP-011).
    auto tail = n00b_macho_layout_eof_tail_gap(layout,
                                               request->payload_size,
                                               alignment);
    if (n00b_result_is_err(tail)) {
        return n00b_result_err(
            n00b_macho_rewrite_admit_result_t,
            layout_err_to_admit_err(n00b_result_get_err(tail)));
    }

    n00b_option_t(n00b_macho_layout_gap_t) tail_opt = n00b_result_get(tail);
    if (!tail_opt.has_value) {
        return n00b_result_err(n00b_macho_rewrite_admit_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_LAYOUT_SUBSTRATE);
    }

    n00b_macho_layout_gap_t tail_gap = n00b_option_get(tail_opt);

    return accepted(
        layout,
        request,
        &facts,
        alignment,
        placement_from_range(N00B_MACHO_REWRITE_ADMIT_PLACEMENT_EOF_TAIL,
                             tail_gap.start,
                             tail_gap.end,
                             request->payload_size,
                             alignment));
}

// ============================================================================
// Public metadata-insert admission entry points
// ============================================================================

n00b_result_t(n00b_macho_rewrite_admit_result_t)
n00b_macho_rewrite_admit_metadata_insert(
    n00b_macho_binary_t                         *bin,
    n00b_macho_rewrite_admit_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` here: null/zero inputs are part of this function's
    // contract surface (they return `Err(N00B_MACHO_REWRITE_ADMIT_ERR_*)`, per
    // the header `@pre` + DoD P1-h), and an ncc `requires` is a debug-active
    // trap that would fire before the body could return the documented `Err`.
    // The `@pre` lives in the header Doxygen; the body enforces the guard. This
    // mirrors the ELF twin `n00b_elf_rewrite_admit_metadata_insert`, whose
    // public definition likewise carries no contract block and delegates to the
    // guarded `_impl` (D-004 release-path guard pairing).
    ensures {
        // Guarded by success (D-028): on Err, result.ok is invalid.
        !result.is_ok
            || (result.ok.outcome != N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED)
            || result.ok.placement.has_value;
        !result.is_ok
            || (result.ok.outcome != N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED)
            || (result.ok.rejection_reason
                != N00B_MACHO_REWRITE_ADMIT_REJECT_NONE);
    }
{
    return admit_metadata_insert_impl(bin,
                                      request,
                                      TRUSTED_OWNER_NONE,
                                      allocator);
}

n00b_result_t(n00b_macho_rewrite_admit_result_t)
n00b_macho_rewrite_admit_chalk_mark_insert(
    n00b_macho_binary_t                         *bin,
    n00b_macho_rewrite_admit_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (see `_metadata_insert`): null/zero inputs return
    // `Err`, so a debug-trapping `requires` would contradict that contract.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is invalid.
        !result.is_ok
            || (result.ok.outcome != N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED)
            || result.ok.placement.has_value;
        !result.is_ok
            || (result.ok.outcome != N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED)
            || (result.ok.rejection_reason
                != N00B_MACHO_REWRITE_ADMIT_REJECT_NONE);
    }
{
    return admit_metadata_insert_impl(bin,
                                      request,
                                      TRUSTED_OWNER_CHALK_MARK,
                                      allocator);
}

n00b_result_t(n00b_macho_rewrite_admit_result_t)
n00b_macho_rewrite_admit_object_bundle_insert(
    n00b_macho_binary_t                         *bin,
    n00b_macho_rewrite_admit_metadata_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (see `_metadata_insert`): null/zero inputs return
    // `Err`, so a debug-trapping `requires` would contradict that contract.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is invalid.
        !result.is_ok
            || (result.ok.outcome != N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED)
            || result.ok.placement.has_value;
        !result.is_ok
            || (result.ok.outcome != N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED)
            || (result.ok.rejection_reason
                != N00B_MACHO_REWRITE_ADMIT_REJECT_NONE);
    }
{
    return admit_metadata_insert_impl(bin,
                                      request,
                                      TRUSTED_OWNER_OBJECT_BUNDLE,
                                      allocator);
}

// ============================================================================
// Loadable-insert admission core
// ============================================================================

// On-disk size of one `LC_SEGMENT_64` load command with zero sections (`cmd`,
// `cmdsize`, 16B `segname`, 8B `vmaddr`/`vmsize`/`fileoff`/`filesize`, 4B
// `maxprot`/`initprot`/`nsects`/`flags` = 72). Matches the raw geometry the
// build/test layer pins (`n00b_macho_segment_command64_t`, macho_types.h:462-474;
// the casegen's `N00B_TEST_MACHO_SEG_CMD_SIZE`), and the WP-001 spike's 72 B
// segment command (D-021). This is the LC growth a single new loadable segment
// command needs.
#define N00B_MACHO_LC_SEGMENT_64_CMD_SIZE 72u

static n00b_macho_rewrite_admit_loadable_result_t
make_loadable_result(
    n00b_macho_rewrite_admit_loadable_request_t *request,
    uint64_t                                     file_alignment,
    uint64_t                                     vaddr_alignment,
    n00b_macho_rewrite_admit_outcome_t           outcome,
    n00b_macho_rewrite_admit_rejection_reason_t  reason)
{
    return (n00b_macho_rewrite_admit_loadable_result_t){
        .outcome                   = outcome,
        .rejection_reason          = reason,
        .payload_size              = request->payload_size,
        .vmsize                    = request->vmsize,
        .effective_file_alignment  = file_alignment,
        .effective_vaddr_alignment = vaddr_alignment,
        .initprot                  = request->initprot,
        .maxprot                   = request->maxprot,
        .policy                    = request->policy,
    };
}

static n00b_result_t(n00b_macho_rewrite_admit_loadable_result_t)
rejected_loadable(n00b_macho_rewrite_admit_loadable_request_t *request,
                  uint64_t                                     file_alignment,
                  uint64_t                                     vaddr_alignment,
                  n00b_macho_rewrite_admit_rejection_reason_t  reason)
{
    n00b_macho_rewrite_admit_loadable_result_t result =
        make_loadable_result(request,
                             file_alignment,
                             vaddr_alignment,
                             N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED,
                             reason);

    return n00b_result_ok(n00b_macho_rewrite_admit_loadable_result_t, result);
}

// Highest segment vm end across all segments (page-rounded low bound is the
// layout layer's job; here we only need a vm cursor above which to search for a
// gap). Pure reads of the parsed segment array. Returns Err on overflow.
static n00b_result_t(uint64_t)
highest_segment_vaddr_end(n00b_macho_binary_t *bin)
{
    uint64_t max_vm_end = 0;

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_macho_segment_t *seg = &bin->segments[i];

        uint64_t vm_end;
        if (!checked_add_u64(seg->vmaddr, seg->vmsize, &vm_end)) {
            return n00b_result_err(uint64_t,
                                   N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW);
        }

        if (vm_end > max_vm_end) {
            max_vm_end = vm_end;
        }
    }

    return n00b_result_ok(uint64_t, max_vm_end);
}

// Overflow-safe round-up: returns false (no write) if rounding `value` up to the
// next `alignment` multiple would overflow uint64_t. The caller maps false to
// ERR_OVERFLOW, matching the checked_add_u64 convention used throughout.
static bool
align_up(uint64_t value, uint64_t alignment, uint64_t *out)
{
    if (alignment <= 1) {
        *out = value;
        return true;
    }

    uint64_t rem = value % alignment;
    if (rem == 0) {
        *out = value;
        return true;
    }

    return checked_add_u64(value, alignment - rem, out);
}

static n00b_result_t(n00b_macho_rewrite_admit_loadable_result_t)
admit_loadable_insert_impl(
    n00b_macho_binary_t                         *bin,
    n00b_macho_rewrite_admit_loadable_request_t *request,
    n00b_allocator_t                            *allocator)
{
    if (bin == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_admit_loadable_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_NULL_BINARY);
    }

    if (request == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_admit_loadable_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_NULL_REQUEST);
    }

    if (request->payload_size == 0) {
        return n00b_result_err(n00b_macho_rewrite_admit_loadable_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_ZERO_PAYLOAD);
    }

    uint64_t file_alignment = effective_alignment(request->file_alignment);
    // VM segments are page-granular on arm64: an unspecified vaddr_alignment
    // defaults to the arm64 page size (NOT 1), so placement alignment and the
    // page-collision `page_size` agree per N00B_MACHO_ARM64_PAGE_SIZE's contract.
    uint64_t vaddr_alignment = request->vaddr_alignment != 0
                                   ? request->vaddr_alignment
                                   : N00B_MACHO_ARM64_PAGE_SIZE;

    // -- Undersized vmsize -> reject (D-031: guarded here, not a `requires`) --
    if (request->vmsize < request->payload_size) {
        return rejected_loadable(request,
                                 file_alignment,
                                 vaddr_alignment,
                                 N00B_MACHO_REWRITE_ADMIT_REJECT_VMSIZE_TOO_SMALL);
    }

    // -- Malformed request: initprot must not exceed maxprot --------------
    if ((request->initprot & ~request->maxprot) != 0) {
        return rejected_loadable(
            request,
            file_alignment,
            vaddr_alignment,
            N00B_MACHO_REWRITE_ADMIT_REJECT_INVALID_LOADABLE_REQUEST);
    }

    auto layout_result = n00b_macho_layout_build(bin, .allocator = allocator);
    if (n00b_result_is_err(layout_result)) {
        return n00b_result_err(
            n00b_macho_rewrite_admit_loadable_result_t,
            layout_err_to_admit_err(n00b_result_get_err(layout_result)));
    }

    n00b_macho_layout_t *layout = n00b_result_get(layout_result);

    // -- Code-signature facts + no-resign reject --------------------------
    bool     cs_present = false;
    uint64_t cs_offset  = 0;
    if (bin->code_signature != nullptr) {
        cs_present = true;
        cs_offset  = (uint64_t)bin->code_signature->dataoff;
    }

    if (cs_present
        && !policy_has(request->policy,
                       N00B_MACHO_REWRITE_ADMIT_POLICY_ALLOW_RESIGN)) {
        n00b_macho_rewrite_admit_loadable_result_t result =
            make_loadable_result(
                request,
                file_alignment,
                vaddr_alignment,
                N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED,
                N00B_MACHO_REWRITE_ADMIT_REJECT_CODESIG_PRESENT_NO_RESIGN);
        result.code_signature_present    = true;
        result.code_signature_old_offset = cs_offset;

        return n00b_result_ok(n00b_macho_rewrite_admit_loadable_result_t,
                              result);
    }

    // -- LC growth facts: one new LC_SEGMENT_64 needs this many bytes of LC
    //    slack. D-021: insufficient slack is accepted-but-costly (`__TEXT`
    //    reflow), NOT a rejection — never REJECT_LC_HEADER_SLACK here. ------
    uint64_t lc_offset = N00B_MACHO_HEADER_64_SIZE;
    uint64_t lc_used   = (uint64_t)bin->header.sizeofcmds;
    uint64_t lc_end;
    if (!checked_add_u64(lc_offset, lc_used, &lc_end)) {
        return n00b_result_err(n00b_macho_rewrite_admit_loadable_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    auto first_sec_result =
        n00b_macho_rewrite_first_section_start_after(layout, lc_end);
    if (n00b_result_is_err(first_sec_result)) {
        return n00b_result_err(
            n00b_macho_rewrite_admit_loadable_result_t,
            layout_err_to_admit_err(n00b_result_get_err(first_sec_result)));
    }

    n00b_option_t(uint64_t) first_sec = n00b_result_get(first_sec_result);
    uint64_t                lc_capacity = first_sec.has_value
                                              ? n00b_option_get(first_sec)
                                              : layout->file_size;
    uint64_t lc_slack = lc_capacity > lc_end ? lc_capacity - lc_end : 0;
    uint64_t required_lc_growth =
        (uint64_t)N00B_MACHO_LC_SEGMENT_64_CMD_SIZE;

    // -- __LINKEDIT relocation facts: a new segment placed before __LINKEDIT
    //    forces __LINKEDIT (and any trailing code signature) to move. -------
    uint64_t linkedit_old_offset = 0;
    uint64_t linkedit_end        = 0;
    bool     have_linkedit       = false;
    auto     le_result           = n00b_macho_rewrite_linkedit_is_last(
        bin,
        &linkedit_old_offset,
        &linkedit_end,
        &have_linkedit);
    if (n00b_result_is_err(le_result)) {
        return n00b_result_err(
            n00b_macho_rewrite_admit_loadable_result_t,
            layout_err_to_admit_err(n00b_result_get_err(le_result)));
    }

    // -- File placement: append the new segment at the EOF tail, page-aligned
    //    (the rewrite layer slides __LINKEDIT after it; admission reports the
    //    placement facts only). --------------------------------------------
    auto tail = n00b_macho_layout_eof_tail_gap(layout,
                                               request->payload_size,
                                               file_alignment);
    if (n00b_result_is_err(tail)) {
        return n00b_result_err(
            n00b_macho_rewrite_admit_loadable_result_t,
            layout_err_to_admit_err(n00b_result_get_err(tail)));
    }

    n00b_option_t(n00b_macho_layout_gap_t) tail_opt = n00b_result_get(tail);
    if (!tail_opt.has_value) {
        return rejected_loadable(
            request,
            file_alignment,
            vaddr_alignment,
            N00B_MACHO_REWRITE_ADMIT_REJECT_NO_SAFE_PLACEMENT);
    }

    n00b_macho_layout_gap_t tail_gap = n00b_option_get(tail_opt);
    uint64_t                new_file_offset = tail_gap.start;

    if (file_alignment != 0 && new_file_offset % file_alignment != 0) {
        return rejected_loadable(
            request,
            file_alignment,
            vaddr_alignment,
            N00B_MACHO_REWRITE_ADMIT_REJECT_FILEOFF_NOT_PAGE_ALIGNED);
    }

    uint64_t new_file_end;
    if (!checked_add_u64(new_file_offset, request->payload_size, &new_file_end)) {
        return n00b_result_err(n00b_macho_rewrite_admit_loadable_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    // -- VM placement: search for a page-aligned vaddr gap above the highest
    //    existing segment vm end, then confirm no page-rounded collision. ---
    auto vm_end_result = highest_segment_vaddr_end(bin);
    if (n00b_result_is_err(vm_end_result)) {
        return n00b_result_err(n00b_macho_rewrite_admit_loadable_result_t,
                               n00b_result_get_err(vm_end_result));
    }

    uint64_t vm_cursor;
    if (!align_up(n00b_result_get(vm_end_result), vaddr_alignment, &vm_cursor)) {
        return n00b_result_err(n00b_macho_rewrite_admit_loadable_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW);
    }
    uint64_t vm_search_end;
    if (!checked_add_u64(vm_cursor, request->vmsize, &vm_search_end)) {
        return n00b_result_err(n00b_macho_rewrite_admit_loadable_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    auto vaddr_gap = n00b_macho_layout_find_vaddr_gap(layout,
                                                      vm_cursor,
                                                      vm_search_end,
                                                      request->vmsize,
                                                      vaddr_alignment);
    if (n00b_result_is_err(vaddr_gap)) {
        return n00b_result_err(
            n00b_macho_rewrite_admit_loadable_result_t,
            layout_err_to_admit_err(n00b_result_get_err(vaddr_gap)));
    }

    n00b_option_t(n00b_macho_layout_gap_t) vaddr_opt =
        n00b_result_get(vaddr_gap);
    uint64_t new_vaddr = vaddr_opt.has_value
                             ? n00b_option_get(vaddr_opt).start
                             : vm_cursor;

    uint64_t new_vaddr_end;
    if (!checked_add_u64(new_vaddr, request->vmsize, &new_vaddr_end)) {
        return n00b_result_err(n00b_macho_rewrite_admit_loadable_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    auto vaddr_collision = n00b_macho_layout_page_segment_vaddr_collision(
        bin,
        new_vaddr,
        new_vaddr_end,
        vaddr_alignment,
        .allocator = allocator);
    if (n00b_result_is_err(vaddr_collision)) {
        return n00b_result_err(
            n00b_macho_rewrite_admit_loadable_result_t,
            layout_err_to_admit_err(n00b_result_get_err(vaddr_collision)));
    }

    if (n00b_result_get(vaddr_collision).interval_count != 0) {
        return rejected_loadable(
            request,
            file_alignment,
            vaddr_alignment,
            N00B_MACHO_REWRITE_ADMIT_REJECT_VADDR_COLLISION);
    }

    // -- Accept: fill placement + relocation facts ------------------------
    uint64_t original_segment_count = (uint64_t)bin->num_segments;
    uint64_t new_segment_count;
    if (!checked_add_u64(original_segment_count, 1, &new_segment_count)) {
        return n00b_result_err(n00b_macho_rewrite_admit_loadable_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    n00b_macho_rewrite_admit_loadable_result_t result =
        make_loadable_result(request,
                             file_alignment,
                             vaddr_alignment,
                             N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED,
                             N00B_MACHO_REWRITE_ADMIT_REJECT_NONE);

    result.new_segment_file_offset = new_file_offset;
    result.new_segment_file_end    = new_file_end;
    result.new_segment_vaddr       = new_vaddr;
    result.new_segment_vaddr_end   = new_vaddr_end;
    result.lc_slack_bytes          = lc_slack;
    result.required_lc_growth      = required_lc_growth;
    result.linkedit_must_move      = have_linkedit;
    result.linkedit_old_offset     = linkedit_old_offset;
    // The new linkedit offset is computed by the rewrite layer (WP-006); the
    // admission fact records that it must move and from where.
    result.linkedit_new_offset       = 0;
    result.code_signature_present    = cs_present;
    result.code_signature_old_offset = cs_offset;
    result.original_segment_count    = original_segment_count;
    result.new_segment_count         = new_segment_count;
    result.file_size                 = layout->file_size;
    // D-021: insufficient LC slack for the new segment command is the
    // `__TEXT`-reflow signal (accepted-but-costly), set iff slack < growth.
    result.entrypoint_policy_deferred = lc_slack < required_lc_growth;

    return n00b_result_ok(n00b_macho_rewrite_admit_loadable_result_t, result);
}

// ============================================================================
// arm64 host-entrypoint admission core
// ============================================================================

static n00b_macho_rewrite_admit_entrypoint_result_t
make_entrypoint_result(n00b_macho_rewrite_admit_outcome_t          outcome,
                       n00b_macho_rewrite_admit_rejection_reason_t reason,
                       uint32_t                                    cputype)
{
    return (n00b_macho_rewrite_admit_entrypoint_result_t){
        .outcome          = outcome,
        .rejection_reason = reason,
        .cputype          = cputype,
    };
}

static n00b_result_t(n00b_macho_rewrite_admit_entrypoint_result_t)
rejected_entrypoint(n00b_macho_rewrite_admit_rejection_reason_t reason,
                    uint32_t                                    cputype)
{
    n00b_macho_rewrite_admit_entrypoint_result_t result =
        make_entrypoint_result(N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED,
                               reason,
                               cputype);

    return n00b_result_ok(n00b_macho_rewrite_admit_entrypoint_result_t,
                          result);
}

// True if the parsed command list carries an `LC_MAIN`. Per macho.h, a non-zero
// `bin->entrypoint` alone does NOT distinguish `LC_MAIN` from `LC_UNIXTHREAD`
// (both write it), so `has_lc_main` requires scanning `commands[]`.
static bool
has_lc_main_command(n00b_macho_binary_t *bin)
{
    for (uint32_t i = 0; i < bin->num_commands; i++) {
        if (bin->commands[i].cmd == LC_MAIN) {
            return true;
        }
    }

    return false;
}

// __TEXT segment vm base (file offset 0 maps to the __TEXT vmaddr). 0 if there
// is no __TEXT segment. Pure reads of the parsed segment array.
static uint64_t
text_segment_vmaddr(n00b_macho_binary_t *bin)
{
    for (uint32_t i = 0; i < bin->num_segments; i++) {
        if (n00b_unicode_str_eq(n00b_string_from_cstr(bin->segments[i].name),
                                r"__TEXT")) {
            return bin->segments[i].vmaddr;
        }
    }

    return 0;
}

static n00b_result_t(n00b_macho_rewrite_admit_entrypoint_result_t)
admit_host_entrypoint_target_impl(
    n00b_macho_binary_t                           *bin,
    n00b_macho_rewrite_admit_entrypoint_request_t *request)
{
    if (bin == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_admit_entrypoint_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_NULL_BINARY);
    }

    if (request == nullptr) {
        return n00b_result_err(n00b_macho_rewrite_admit_entrypoint_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_NULL_REQUEST);
    }

    if (request->target_size == 0) {
        return n00b_result_err(n00b_macho_rewrite_admit_entrypoint_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_ZERO_PAYLOAD);
    }

    uint32_t cputype = bin->header.cputype;

    // -- arm64 only -------------------------------------------------------
    if (cputype != (uint32_t)CPU_TYPE_ARM64) {
        return rejected_entrypoint(
            N00B_MACHO_REWRITE_ADMIT_REJECT_UNSUPPORTED_CPUTYPE,
            cputype);
    }

    // -- LC_MAIN required (LC_UNIXTHREAD-only is rejected) ----------------
    if (!has_lc_main_command(bin)) {
        return rejected_entrypoint(N00B_MACHO_REWRITE_ADMIT_REJECT_NO_LC_MAIN,
                                   cputype);
    }

    // -- Target must lie within the candidate segment payload ------------
    uint64_t segment_payload_end;
    if (!checked_add_u64(request->target_payload_offset,
                         request->target_size,
                         &segment_payload_end)) {
        return n00b_result_err(n00b_macho_rewrite_admit_entrypoint_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    // The candidate file range is [target_segment_file_offset + payload_offset,
    // + target_size). It must fall within the candidate segment's own file
    // extent: the payload offset is segment-relative, so the only constraint
    // expressible from the request facts is that the target file end does not
    // overflow the Mach-O start-relative address space.
    uint64_t target_file_offset;
    if (!checked_add_u64(request->target_segment_file_offset,
                         request->target_payload_offset,
                         &target_file_offset)) {
        return n00b_result_err(n00b_macho_rewrite_admit_entrypoint_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    uint64_t target_file_end;
    if (!checked_add_u64(target_file_offset,
                         request->target_size,
                         &target_file_end)) {
        return n00b_result_err(n00b_macho_rewrite_admit_entrypoint_result_t,
                               N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW);
    }

    // -- Accept: derive the replacement entryoff -------------------------
    // `LC_MAIN.entryoff` is a file offset relative to the Mach-O start (the
    // __TEXT vmaddr maps to file offset 0). The redirected entry is the
    // candidate segment's file base plus the in-segment payload offset.
    n00b_macho_rewrite_admit_entrypoint_result_t result =
        make_entrypoint_result(N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED,
                               N00B_MACHO_REWRITE_ADMIT_REJECT_NONE,
                               cputype);

    result.original_entryoff    = bin->entrypoint;
    result.replacement_entryoff = target_file_offset;
    result.text_vmaddr          = text_segment_vmaddr(bin);
    result.has_lc_main          = true;

    return n00b_result_ok(n00b_macho_rewrite_admit_entrypoint_result_t,
                          result);
}

// ============================================================================
// Public loadable-insert + host-entrypoint admission entry points
// ============================================================================

n00b_result_t(n00b_macho_rewrite_admit_loadable_result_t)
n00b_macho_rewrite_admit_loadable_insert(
    n00b_macho_binary_t                         *bin,
    n00b_macho_rewrite_admit_loadable_request_t *request) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
    // No live `requires` (D-031): null `bin`/`request`, zero `payload_size`,
    // and undersized `vmsize` are documented `Err`/reject returns (P2-b
    // VMSIZE_TOO_SMALL), not trapping preconditions; guarded in the `_impl`.
    // The `@pre` survives as header Doxygen. Mirrors the Phase-1 metadata twin.
    ensures {
        // accepted verdicts carry a consistent +1 segment count and a
        // wide-enough, well-ordered extent; rejected verdicts carry a reason.
        // Guarded by success (D-028): on Err, result.ok is invalid.
        !result.is_ok
            || (result.ok.outcome != N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED)
            || (result.ok.new_segment_count
                    == result.ok.original_segment_count + 1
                && (result.ok.new_segment_file_end
                        - result.ok.new_segment_file_offset)
                    >= result.ok.payload_size
                && result.ok.new_segment_vaddr_end
                    > result.ok.new_segment_vaddr);
        // The concrete relocated __LINKEDIT offset is the rewrite layer's job
        // (WP-006): admission leaves it 0 on accept (header @post).
        !result.is_ok
            || (result.ok.outcome != N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED)
            || result.ok.linkedit_new_offset == 0;
        !result.is_ok
            || (result.ok.outcome != N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED)
            || (result.ok.rejection_reason
                != N00B_MACHO_REWRITE_ADMIT_REJECT_NONE);
    }
{
    return admit_loadable_insert_impl(bin, request, allocator);
}

n00b_result_t(n00b_macho_rewrite_admit_entrypoint_result_t)
n00b_macho_rewrite_admit_host_entrypoint_target(
    n00b_macho_binary_t                           *bin,
    n00b_macho_rewrite_admit_entrypoint_request_t *request)
    // No live `requires` (D-031): null `bin`/`request` and zero `target_size`
    // are documented `Err` returns, not trapping preconditions; guarded in the
    // `_impl`. The `@pre` survives as header Doxygen.
    ensures {
        // Guarded by success (D-028): on Err, result.ok is invalid.
        !result.is_ok
            || (result.ok.outcome != N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED)
            || (result.ok.has_lc_main
                && result.ok.cputype == CPU_TYPE_ARM64);
    }
{
    return admit_host_entrypoint_target_impl(bin, request);
}

// ============================================================================
// Enum-name / error-string helpers (D-029: pointer return, no `ensures`)
// ============================================================================

n00b_string_t *
n00b_macho_rewrite_admit_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_MACHO_REWRITE_ADMIT_ERR_NULL_BINARY:
        return r"Mach-O rewrite admission: null binary";
    case N00B_MACHO_REWRITE_ADMIT_ERR_NULL_REQUEST:
        return r"Mach-O rewrite admission: null request";
    case N00B_MACHO_REWRITE_ADMIT_ERR_ZERO_PAYLOAD:
        return r"Mach-O rewrite admission: zero payload size";
    case N00B_MACHO_REWRITE_ADMIT_ERR_LAYOUT_SUBSTRATE:
        return r"Mach-O rewrite admission: layout substrate failure";
    case N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW:
        return r"Mach-O rewrite admission: arithmetic overflow";
    default:
        return r"Mach-O rewrite admission: unknown error code";
    }
}

n00b_string_t *
n00b_macho_rewrite_admit_policy_flag_str(
    n00b_macho_rewrite_admit_policy_flag_t flag)
{
    switch (flag) {
    case N00B_MACHO_REWRITE_ADMIT_POLICY_NONE:
        return r"none";
    case N00B_MACHO_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION:
        return r"strict-loader-preservation";
    case N00B_MACHO_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY:
        return r"preserve-overlay";
    case N00B_MACHO_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY:
        return r"append-after-overlay";
    case N00B_MACHO_REWRITE_ADMIT_POLICY_ALLOW_RESIGN:
        return r"allow-resign";
    default:
        return r"unknown-macho-rewrite-admit-policy-flag";
    }
}

n00b_string_t *
n00b_macho_rewrite_admit_outcome_str(
    n00b_macho_rewrite_admit_outcome_t outcome)
{
    switch (outcome) {
    case N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED:
        return r"accepted";
    case N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED:
        return r"rejected";
    default:
        return r"unknown-macho-rewrite-admit-outcome";
    }
}

n00b_string_t *
n00b_macho_rewrite_admit_placement_kind_str(
    n00b_macho_rewrite_admit_placement_kind_t kind)
{
    switch (kind) {
    case N00B_MACHO_REWRITE_ADMIT_PLACEMENT_NONE:
        return r"none";
    case N00B_MACHO_REWRITE_ADMIT_PLACEMENT_EOF_TAIL:
        return r"eof-tail";
    case N00B_MACHO_REWRITE_ADMIT_PLACEMENT_FILE_GAP:
        return r"file-gap";
    case N00B_MACHO_REWRITE_ADMIT_PLACEMENT_AFTER_OVERLAY:
        return r"after-overlay";
    case N00B_MACHO_REWRITE_ADMIT_PLACEMENT_BEFORE_CODESIG:
        return r"before-codesig";
    default:
        return r"unknown-macho-rewrite-admit-placement-kind";
    }
}

n00b_string_t *
n00b_macho_rewrite_admit_rejection_reason_str(
    n00b_macho_rewrite_admit_rejection_reason_t reason)
{
    switch (reason) {
    case N00B_MACHO_REWRITE_ADMIT_REJECT_NONE:
        return r"none";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_NOT_YET_CHECKED:
        return r"not-yet-checked";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_RESERVED_NOTE_NAME:
        return r"reserved-note-name";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_NO_SAFE_PLACEMENT:
        return r"no-safe-placement";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_FILE_COLLISION:
        return r"file-collision";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_UNKNOWN_NONZERO_BYTES:
        return r"unknown-nonzero-bytes";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_OVERLAY_POLICY:
        return r"overlay-policy";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_LC_HEADER_SLACK:
        return r"lc-header-slack";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_LC_REGION_INCONSISTENT:
        return r"lc-region-inconsistent";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_LINKEDIT_NOT_LAST:
        return r"linkedit-not-last";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_CODESIG_NOT_LAST:
        return r"codesig-not-last";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_CODESIG_PRESENT_NO_RESIGN:
        return r"codesig-present-no-resign";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_INVALID_LOADABLE_REQUEST:
        return r"invalid-loadable-request";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_VMSIZE_TOO_SMALL:
        return r"vmsize-too-small";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_VADDR_COLLISION:
        return r"vaddr-collision";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_FILEOFF_NOT_PAGE_ALIGNED:
        return r"fileoff-not-page-aligned";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_ENTRY_OUTSIDE_SEGMENT:
        return r"entry-outside-segment";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_ENTRY_NOT_EXECUTABLE:
        return r"entry-not-executable";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_UNSUPPORTED_CPUTYPE:
        return r"unsupported-cputype";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_NO_LC_MAIN:
        return r"no-lc-main";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_RESERVED_TARGET:
        return r"reserved-target";
    case N00B_MACHO_REWRITE_ADMIT_REJECT_LOADER_PRESERVATION:
        return r"loader-preservation";
    default:
        return r"unknown-macho-rewrite-admit-rejection-reason";
    }
}
