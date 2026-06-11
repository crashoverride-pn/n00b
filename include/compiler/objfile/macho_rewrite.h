/**
 * @file macho_rewrite.h
 * @brief Surgical Mach-O rewrite planning and apply API.
 *
 * This layer turns strict rewrite admission facts into explicit patch plans,
 * then applies accepted plans to new in-memory byte buffers. Planning and
 * application never mutate the parsed Mach-O object or its original byte stream.
 *
 * Mach-O delta from ELF: there is no PHTAB to grow, so all the `*_phtab_*` /
 * `PT_PHDR` machinery from ELF collapses to load-command region growth plus
 * `__LINKEDIT` (and trailing code-signature) relocation. When the available
 * load-command header slack is smaller than the new `LC_SEGMENT_64` cmdsize,
 * the plan path is `__TEXT` section reflow (sliding `__TEXT` sections to open
 * load-command room and growing `__TEXT`), not merely `__LINKEDIT` relocation
 * (D-021). The patch-kind enum is organized around this. The entrypoint
 * redirect is `LC_MAIN.entryoff` (a file offset), not ELF's `e_entry` (a vaddr).
 *
 * Mirrors `elf_rewrite.h` for the Mach-O arm64 backend.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "adt/array.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_rewrite_admit.h"

// ============================================================================
// Error codes
// ============================================================================

#define N00B_MACHO_REWRITE_OK 0
#define N00B_MACHO_REWRITE_ERR_NULL_BINARY       (-4401)
#define N00B_MACHO_REWRITE_ERR_NULL_REQUEST      (-4402)
#define N00B_MACHO_REWRITE_ERR_NULL_NOTE_OWNER   (-4403)
#define N00B_MACHO_REWRITE_ERR_NULL_PAYLOAD      (-4404)
#define N00B_MACHO_REWRITE_ERR_ZERO_PAYLOAD      (-4405)
#define N00B_MACHO_REWRITE_ERR_TARGET_PROFILE    (-4406)
#define N00B_MACHO_REWRITE_ERR_ADMISSION         (-4407)
#define N00B_MACHO_REWRITE_ERR_OVERFLOW          (-4408)
#define N00B_MACHO_REWRITE_ERR_NULL_PLAN         (-4409)
#define N00B_MACHO_REWRITE_ERR_PLAN_REJECTED     (-4410)
#define N00B_MACHO_REWRITE_ERR_UNSUPPORTED_PLAN  (-4411)
#define N00B_MACHO_REWRITE_ERR_APPLY             (-4412)
#define N00B_MACHO_REWRITE_ERR_PARSE_AFTER_APPLY (-4413)
#define N00B_MACHO_REWRITE_ERR_NOTE_NOT_FOUND    (-4414)
#define N00B_MACHO_REWRITE_ERR_TRUSTED_NAME      (-4415)

// ============================================================================
// Plan outcome / operation / rejection / profile / patch-kind enums
// ============================================================================

typedef enum {
    N00B_MACHO_REWRITE_PLAN_ACCEPTED,
    N00B_MACHO_REWRITE_PLAN_REJECTED,
} n00b_macho_rewrite_plan_outcome_t;

typedef enum {
    N00B_MACHO_REWRITE_OPERATION_METADATA_INSERT,
    N00B_MACHO_REWRITE_OPERATION_CHALK_MARK_DELETE,
    N00B_MACHO_REWRITE_OPERATION_CHALK_MARK_REPLACE,
    N00B_MACHO_REWRITE_OPERATION_OBJECT_BUNDLE_REPLACE,
    N00B_MACHO_REWRITE_OPERATION_OBJECT_BUNDLE_DELETE,
    N00B_MACHO_REWRITE_OPERATION_LOADABLE_INSERT,
} n00b_macho_rewrite_operation_t;

typedef enum {
    N00B_MACHO_REWRITE_REJECT_NONE,
    N00B_MACHO_REWRITE_REJECT_TARGET_PROFILE,
    N00B_MACHO_REWRITE_REJECT_ADMISSION,
    N00B_MACHO_REWRITE_REJECT_LC_PLACEMENT,
    N00B_MACHO_REWRITE_REJECT_NCMDS_PROMOTION,        // sizeofcmds overflow
    N00B_MACHO_REWRITE_REJECT_OVERFLOW,
    N00B_MACHO_REWRITE_REJECT_CHALK_MARK_NOT_FOUND,
    N00B_MACHO_REWRITE_REJECT_CHALK_MARK_UNSUPPORTED,
    N00B_MACHO_REWRITE_REJECT_TRUSTED_NAME,
    N00B_MACHO_REWRITE_REJECT_OBJECT_BUNDLE_NOT_FOUND,
    N00B_MACHO_REWRITE_REJECT_OBJECT_BUNDLE_DUPLICATE,
    N00B_MACHO_REWRITE_REJECT_OBJECT_BUNDLE_UNSUPPORTED,
    N00B_MACHO_REWRITE_REJECT_LOADABLE_PLACEMENT,
    N00B_MACHO_REWRITE_REJECT_LOADABLE_ADDRESS,
    N00B_MACHO_REWRITE_REJECT_LINKEDIT_RELOCATION,
    N00B_MACHO_REWRITE_REJECT_CODESIG_INTERACTION,
} n00b_macho_rewrite_rejection_reason_t;

/** Packager-compatible target shape evaluation (mirror of ELF profile). */
typedef enum {
    N00B_MACHO_REWRITE_PROFILE_OK,
    N00B_MACHO_REWRITE_PROFILE_BAD_MAGIC,         // not MH_MAGIC_64
    N00B_MACHO_REWRITE_PROFILE_BAD_CPUTYPE,       // not arm64 (rewrite target)
    N00B_MACHO_REWRITE_PROFILE_BAD_FILETYPE,      // not MH_EXECUTE/MH_DYLIB/...
    N00B_MACHO_REWRITE_PROFILE_LC_REGION_BOUNDS,  // sizeofcmds past 1st segment
    N00B_MACHO_REWRITE_PROFILE_NO_LINKEDIT,
    N00B_MACHO_REWRITE_PROFILE_LINKEDIT_NOT_LAST,
    N00B_MACHO_REWRITE_PROFILE_CODESIG_NOT_LAST,
    N00B_MACHO_REWRITE_PROFILE_FAT_UNSUPPORTED,   // single-slice API only
    N00B_MACHO_REWRITE_PROFILE_OVERLAP,
} n00b_macho_rewrite_target_profile_reason_t;

typedef enum {
    // metadata insert/replace:
    N00B_MACHO_REWRITE_PATCH_MACH_HEADER,        // ncmds/sizeofcmds
    N00B_MACHO_REWRITE_PATCH_LOAD_COMMANDS,      // appended/grown LC region
    N00B_MACHO_REWRITE_PATCH_PAYLOAD,            // LC_NOTE payload bytes
    N00B_MACHO_REWRITE_PATCH_STALE_PAYLOAD,      // zeroed old payload (replace)
    // __LINKEDIT relocation:
    N00B_MACHO_REWRITE_PATCH_LINKEDIT_RELOCATED, // moved __LINKEDIT bytes
    N00B_MACHO_REWRITE_PATCH_LINKEDIT_CMD,       // updated segment cmd off/size
    N00B_MACHO_REWRITE_PATCH_SYMTAB_CMD,         // symbol-table LC offsets: LC_SYMTAB symoff/stroff AND LC_DYSYMTAB offsets (shared kind)
    N00B_MACHO_REWRITE_PATCH_DYLD_INFO_CMD,      // updated dyld-info offsets
    N00B_MACHO_REWRITE_PATCH_LINKEDIT_DATA_CMD,  // func_starts/dic/fixups cmds
    N00B_MACHO_REWRITE_PATCH_CODESIG_CMD,        // updated LC_CODE_SIGNATURE off
    // loadable insert:
    N00B_MACHO_REWRITE_PATCH_NEW_SEGMENT_CMD,    // appended LC_SEGMENT_64
    N00B_MACHO_REWRITE_PATCH_LOADABLE_PAYLOAD,   // new segment payload bytes
    N00B_MACHO_REWRITE_PATCH_LOADABLE_PADDING,   // zeroed page padding
    // __TEXT-section reflow (D-021 / D-032): taken when LC header slack is
    // smaller than the new LC_SEGMENT_64 cmdsize, so the LC region cannot grow
    // in place and __TEXT sections must slide forward to open header room.
    N00B_MACHO_REWRITE_PATCH_TEXT_SECTIONS_RELOCATED, // slid __TEXT section bytes
    N00B_MACHO_REWRITE_PATCH_TEXT_CMD,           // __TEXT seg grow + sect offsets
    // entrypoint:
    // NOTE: unlike every other patch kind (whose file_offset/file_end are absolute
    // file offsets), the LC_MAIN_ENTRYOFF patch's file_offset is the within-command
    // RELATIVE entryoff offset (8). The absolute output location is apply-resolved
    // (the apply scans the OUTPUT for LC_MAIN, since the inserted LC_SEGMENT_64 +
    // any __TEXT reflow shift the command's position). Consumers iterating the
    // patch array must not treat this kind's file_offset as absolute.
    N00B_MACHO_REWRITE_PATCH_LC_MAIN_ENTRYOFF,   // patched LC_MAIN.entryoff (relative offset)
} n00b_macho_rewrite_patch_kind_t;

// ============================================================================
// Requests, profile, patch, plans
// ============================================================================

typedef struct n00b_macho_rewrite_metadata_request {
    n00b_string_t                    *note_owner;
    n00b_string_t                    *note_name;
    n00b_buffer_t                    *payload;
    uint64_t                          file_alignment;
    n00b_option_t(uint64_t)           preferred_file_offset;
    n00b_macho_rewrite_admit_policy_t policy;
} n00b_macho_rewrite_metadata_request_t;

typedef struct n00b_macho_rewrite_loadable_request {
    n00b_buffer_t                    *payload;
    uint32_t                          initprot;
    uint32_t                          maxprot;
    uint64_t                          file_alignment;
    uint64_t                          vaddr_alignment;
    uint64_t                          vmsize;
    n00b_macho_rewrite_admit_policy_t policy;
} n00b_macho_rewrite_loadable_request_t;

typedef struct n00b_macho_rewrite_target_profile {
    n00b_macho_rewrite_target_profile_reason_t reason;
    int      packager_errcode;
    uint64_t file_size;
    uint64_t command_count;       // ncmds
    uint64_t sizeofcmds;
    uint64_t lc_region_offset;
    uint64_t lc_region_capacity;  // to first segment file base
    uint64_t segment_count;
    uint64_t linkedit_offset;
    uint64_t linkedit_size;
    bool     code_signature_present;
    uint64_t code_signature_offset;
    uint64_t code_signature_size;
} n00b_macho_rewrite_target_profile_t;

typedef struct n00b_macho_rewrite_patch {
    n00b_macho_rewrite_patch_kind_t kind;
    uint64_t file_offset;
    uint64_t file_end;
    uint64_t original_file_offset;
    uint64_t original_file_end;
} n00b_macho_rewrite_patch_t;

typedef struct n00b_macho_rewrite_plan {
    n00b_macho_rewrite_operation_t         operation;
    n00b_macho_rewrite_plan_outcome_t      outcome;
    n00b_macho_rewrite_rejection_reason_t  rejection_reason;
    n00b_macho_rewrite_target_profile_t    target_profile;
    n00b_macho_rewrite_admit_result_t      admission;
    n00b_array_t(n00b_macho_rewrite_patch_t) patches;
    n00b_string_t                         *note_owner;
    n00b_string_t                         *note_name;
    n00b_buffer_t                         *payload;
    uint64_t                               note_alignment;
    uint64_t                               file_size;       // output size
    uint64_t                               original_command_count;
    uint64_t                               new_command_count;
    uint64_t                               removed_payload_offset; // replace
    uint64_t                               removed_payload_end;
    uint64_t                               payload_offset;  // new payload base
    uint64_t                               payload_end;
} n00b_macho_rewrite_plan_t;

typedef struct n00b_macho_rewrite_loadable_plan {
    n00b_macho_rewrite_plan_outcome_t          outcome;
    n00b_macho_rewrite_rejection_reason_t      rejection_reason;
    n00b_macho_rewrite_target_profile_t        target_profile;
    n00b_macho_rewrite_admit_loadable_result_t admission;
    n00b_array_t(n00b_macho_rewrite_patch_t)   patches;
    n00b_macho_binary_t                       *source_binary;  // same-binary guard
    n00b_buffer_t                             *payload;
    uint64_t                                   new_segment_file_offset;
    uint64_t                                   new_segment_file_end;
    uint64_t                                   new_segment_vaddr;
    uint64_t                                   new_segment_vaddr_end;
    uint64_t                                   vmsize;
    uint64_t                                   linkedit_old_offset;
    uint64_t                                   linkedit_new_offset;
    bool                                       linkedit_moved;
    bool                                       code_signature_present;
    uint64_t                                   original_entryoff;     // LC_MAIN
    uint64_t                                   replacement_entryoff;
    uint64_t                                   file_size;             // output
    uint64_t                                   original_segment_count;
    uint64_t                                   new_segment_count;
    uint32_t                                   initprot;
    uint32_t                                   maxprot;
    uint64_t                                   file_alignment;
    uint64_t                                   vaddr_alignment;
    bool                                       entrypoint_policy_deferred;
    bool                                       entrypoint_patch_enabled;
    // __TEXT-section reflow facts (D-032). `text_reflow_active` is set when LC
    // header slack was exhausted and the plan slid `__TEXT` sections forward by
    // `text_slide_bytes` (page-aligned) to open load-command room, growing the
    // `__TEXT` segment to `text_new_filesize`/`text_new_vmsize`. All zero on the
    // accept-without-reflow path.
    bool                                       text_reflow_active;
    uint64_t                                   text_slide_bytes;
    uint64_t                                   text_new_filesize;
    uint64_t                                   text_new_vmsize;
} n00b_macho_rewrite_loadable_plan_t;

typedef enum {
    N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_NONE,
    N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_PLAN,
    N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_PLAN,
    N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_CPUTYPE,
    N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_FILETYPE,
    N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_NO_LC_MAIN,
    N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_TARGET_OUT_OF_RANGE,
    N00B_MACHO_REWRITE_HOST_ENTRYPOINT_REJECT_OVERFLOW,
} n00b_macho_rewrite_host_entrypoint_rejection_reason_t;

typedef struct n00b_macho_rewrite_host_entrypoint_target {
    n00b_macho_rewrite_plan_outcome_t                     outcome;
    n00b_macho_rewrite_host_entrypoint_rejection_reason_t rejection_reason;
    uint64_t original_entryoff;
    uint64_t replacement_entryoff;
    uint64_t target_payload_offset;
    uint64_t target_size;
    uint64_t target_file_offset;
    uint64_t target_file_end;
    uint64_t target_vaddr;
    uint64_t target_vaddr_end;
    uint64_t segment_file_offset;
    uint64_t segment_file_end;
    uint64_t segment_vaddr;
    uint64_t segment_vaddr_end;
    uint32_t cputype;
    bool     trampoline_emitted;  // arm64 MVP: false (direct entryoff redirect)
    uint64_t trampoline_size;     // 0
} n00b_macho_rewrite_host_entrypoint_target_t;

// ============================================================================
// Metadata plan functions
// ============================================================================

/**
 * @brief Plan insertion of one non-loadable LC_NOTE metadata payload.
 *
 * The request borrows `note_owner`/`note_name`/`payload`. Accepted plans
 * describe the changed file ranges (mach_header ncmds/sizeofcmds, grown
 * load-command region, payload bytes, and any forced __LINKEDIT/code-signature
 * relocation) but perform no writes. Rejected plans use stable reasons.
 *
 * @param bin Parsed Mach-O object.
 * @param request Metadata insertion request.
 * @kw allocator Defaults to `nullptr`; owns the returned plan and patch array.
 * @return Ok(plan) for accepted or rejected plans, or Err(N00B_MACHO_REWRITE_ERR_*).
 * @pre (Advisory; D-031.) `bin`, `request`, `request->note_owner`, and
 *      `request->payload` are non-null and `request->payload->byte_len` is
 *      nonzero. These are NOT trapping preconditions: a null/zero input is a
 *      documented `Err` return (`_ERR_NULL_BINARY/_REQUEST/_NULL_NOTE_OWNER/
 *      _NULL_PAYLOAD/_ZERO_PAYLOAD`), guarded in the body, not a `requires`.
 * @post `bin`, its stream, and its parsed segment/section arrays are not modified.
 *       (no-`old` limit.)
 * @post On accept, `result.ok->payload_end - result.ok->payload_offset
 *       == request->payload->byte_len` and
 *       `result.ok->new_command_count >= result.ok->original_command_count`.
 */
extern n00b_result_t(n00b_macho_rewrite_plan_t *)
n00b_macho_rewrite_plan_metadata_insert(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan insertion of a trusted Chalk LC_NOTE metadata payload.
 *
 * As @ref n00b_macho_rewrite_plan_metadata_insert, but accepts only the
 * reserved Chalk `data_owner`; a non-matching owner rejects with a
 * trusted-name reason.
 *
 * @param bin Parsed Mach-O object.
 * @param request Metadata insertion request.
 * @kw allocator Defaults to `nullptr`; owns the returned plan and patch array.
 * @return Ok(plan) accepted/rejected, or Err(N00B_MACHO_REWRITE_ERR_*).
 * @pre `bin`, `request`, `request->note_owner`, and `request->payload` are non-null.
 * @pre `request->payload->byte_len` is nonzero.
 * @post `bin`, its stream, and its parsed arrays are not modified. (no-`old` limit.)
 * @post On accept, `result.ok->payload_end - result.ok->payload_offset
 *       == request->payload->byte_len`.
 */
extern n00b_result_t(n00b_macho_rewrite_plan_t *)
n00b_macho_rewrite_plan_chalk_mark_insert(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan insertion of a trusted N00b object-bundle LC_NOTE payload.
 *
 * As @ref n00b_macho_rewrite_plan_metadata_insert, but accepts only the
 * reserved bundle `data_owner`; a non-matching owner rejects with a
 * trusted-name reason.
 *
 * @param bin Parsed Mach-O object.
 * @param request Metadata insertion request.
 * @kw allocator Defaults to `nullptr`; owns the returned plan and patch array.
 * @return Ok(plan) accepted/rejected, or Err(N00B_MACHO_REWRITE_ERR_*).
 * @pre `bin`, `request`, `request->note_owner`, and `request->payload` are non-null.
 * @pre `request->payload->byte_len` is nonzero.
 * @post `bin`, its stream, and its parsed arrays are not modified. (no-`old` limit.)
 * @post On accept, `result.ok->payload_end - result.ok->payload_offset
 *       == request->payload->byte_len`.
 */
extern n00b_result_t(n00b_macho_rewrite_plan_t *)
n00b_macho_rewrite_plan_object_bundle_insert(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan removal of the trusted Chalk LC_NOTE metadata payload.
 *
 * Accepted plans zero the stale payload region; rejected plans report that no
 * Chalk mark was found.
 *
 * @param bin Parsed Mach-O object.
 * @kw allocator Defaults to `nullptr`; owns the returned plan and patch array.
 * @return Ok(plan) accepted/rejected, or Err(N00B_MACHO_REWRITE_ERR_*).
 * @pre `bin`, `bin->stream`, and `bin->stream->buf` are non-null.
 * @post `bin`, its stream, and its parsed arrays are not modified. (no-`old` limit.)
 * @post On accept, `result.ok->removed_payload_end
 *       > result.ok->removed_payload_offset`.
 */
extern n00b_result_t(n00b_macho_rewrite_plan_t *)
n00b_macho_rewrite_plan_chalk_mark_delete(
    n00b_macho_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan removal of the trusted N00b object-bundle LC_NOTE payload.
 *
 * Owner-parameterized twin of @ref n00b_macho_rewrite_plan_chalk_mark_delete:
 * locates the bundle-owned carrier (reserved owner `N00B_MACHO_BUNDLE_NOTE_OWNER`),
 * drops its LC_NOTE command from the load-command region, and removes its
 * payload from `__LINKEDIT`, producing an output SMALLER than the input.
 * Accepted plans carry `operation == OBJECT_BUNDLE_DELETE`; rejected plans
 * report that no bundle carrier was found
 * (`N00B_MACHO_REWRITE_REJECT_OBJECT_BUNDLE_NOT_FOUND`). The bundle payload is
 * required to be the file tail (the carrier insert/marking invariant).
 *
 * @param bin Parsed Mach-O object.
 * @kw allocator Defaults to `nullptr`; owns the returned plan and patch array.
 * @return Ok(plan) accepted/rejected, or Err(N00B_MACHO_REWRITE_ERR_*).
 * @pre (Advisory; D-031.) `bin`, `bin->stream`, and `bin->stream->buf` are
 *      non-null. A null `bin`/`bin->stream`/`bin->stream->buf` is a documented
 *      `Err` return (`_ERR_NULL_BINARY`), guarded in the body, not a `requires`.
 * @post `bin`, its stream, and its parsed arrays are not modified. (no-`old` limit.)
 * @post On accept, `result.ok->removed_payload_end
 *       > result.ok->removed_payload_offset`.
 */
extern n00b_result_t(n00b_macho_rewrite_plan_t *)
n00b_macho_rewrite_plan_object_bundle_delete(
    n00b_macho_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan replacement of the trusted Chalk LC_NOTE metadata payload.
 *
 * Accepted plans zero the prior payload region and place the new payload;
 * rejected plans report that no Chalk mark was found.
 *
 * @param bin Parsed Mach-O object.
 * @param request Metadata replacement request.
 * @kw allocator Defaults to `nullptr`; owns the returned plan and patch array.
 * @return Ok(plan) accepted/rejected, or Err(N00B_MACHO_REWRITE_ERR_*).
 * @pre `bin`, `request`, `request->note_owner`, and `request->payload` are non-null.
 * @pre `request->payload->byte_len` is nonzero.
 * @post `bin`, its stream, and its parsed arrays are not modified. (no-`old` limit.)
 * @post On accept, `result.ok->removed_payload_end
 *       > result.ok->removed_payload_offset`.
 */
extern n00b_result_t(n00b_macho_rewrite_plan_t *)
n00b_macho_rewrite_plan_chalk_mark_replace(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan replacement of the trusted N00b object-bundle LC_NOTE payload.
 *
 * Accepted plans zero the prior carrier payload and place the new payload;
 * rejected plans report that no prior bundle carrier was found.
 *
 * @param bin Parsed Mach-O object.
 * @param request Metadata replacement request.
 * @kw allocator Defaults to `nullptr`; owns the returned plan and patch array.
 * @return Ok(plan) accepted/rejected, or Err(N00B_MACHO_REWRITE_ERR_*).
 * @pre `bin`, `request`, `request->note_owner`, and `request->payload` are non-null.
 * @pre `request->payload->byte_len` is nonzero.
 * @post `bin`, its stream, and its parsed arrays are not modified. (no-`old` limit.)
 * @post On accept, `result.ok->removed_payload_end
 *       > result.ok->removed_payload_offset` (a prior carrier was located).
 */
extern n00b_result_t(n00b_macho_rewrite_plan_t *)
n00b_macho_rewrite_plan_object_bundle_replace(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Loadable plan + entrypoint plan/enable
// ============================================================================

/**
 * @brief Plan insertion of one LC_SEGMENT_64 without emitting bytes.
 *
 * Accepted plans expose stable facts: target profile, admission, new-segment
 * file/vm placement, whether __LINKEDIT and any trailing code signature must
 * move, segment counts, and concrete patch ranges. Entrypoint patch facts are
 * disabled by default. The plan borrows @p bin for the same-binary apply guard.
 *
 * Load-command-slack exhaustion drives a `__TEXT` section-reflow plan path
 * (D-021): when the available LC header slack is less than the new
 * `LC_SEGMENT_64` cmdsize, accepted plans slide `__TEXT` sections to open
 * load-command room and grow `__TEXT` (carried in the patch array as
 * `__TEXT`-reflow patches), rather than relying on `__LINKEDIT` relocation
 * alone. The WP-001 spike confirmed this is required (32 B slack vs a 72 B
 * segment command forced +1 page `__TEXT` growth + a 2-page `__LINKEDIT` shift).
 *
 * @param bin Parsed arm64 Mach-O object.
 * @param request Loadable-segment insertion request.
 * @kw allocator Defaults to `nullptr`; owns the returned plan.
 * @return Ok(plan) accepted/rejected, or Err(N00B_MACHO_REWRITE_ERR_*).
 * @pre `bin`, `request`, and `request->payload` are non-null. (Advisory; D-031.)
 * @pre `request->payload->byte_len` is nonzero. (Advisory; D-031.)
 * @pre `request->vmsize >= request->payload->byte_len`. (Advisory; D-031 —
 *      null/zero/undersized inputs are documented `Err`/reject returns guarded
 *      in the body, not trapping preconditions.)
 * @post `bin`, its stream, and parsed arrays are not modified. (no-`old` limit.)
 * @post On accept, `result.ok->new_segment_count
 *       == result.ok->original_segment_count + 1` and
 *       `result.ok->entrypoint_patch_enabled == false`.
 * @post On accept when load-command slack is exhausted, the plan path is
 *       `__TEXT` section reflow (the patch array carries the reflow ranges),
 *       not `__LINKEDIT`-only relocation (D-021).
 */
extern n00b_result_t(n00b_macho_rewrite_loadable_plan_t *)
n00b_macho_rewrite_plan_loadable_insert(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_loadable_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Validate static arm64 LC_MAIN entrypoint redirection for a loadable plan.
 *
 * Manifest- and bundle-agnostic. Accepts only apply-able loadable plans for
 * arm64 MH_EXECUTE with an LC_MAIN, and a target range expressed as an offset
 * within the planned segment payload. Accepted results derive the concrete
 * replacement `entryoff` (a file offset) and can be passed to
 * @ref n00b_macho_rewrite_loadable_plan_enable_entrypoint.
 *
 * @param bin Parsed Mach-O object used to produce @p plan.
 * @param plan Accepted loadable plan.
 * @param target_payload_offset Start of the target within the planned payload.
 * @param target_size Bytes of the target range.
 * @return Ok(target facts) accepted/rejected, or Err(N00B_MACHO_REWRITE_ERR_*).
 * @pre (Advisory; D-031.) `bin` and `plan` are non-null and `target_size` is
 *      nonzero. These are NOT trapping preconditions: a null `bin`/`plan` is a
 *      documented `Err` return (`_ERR_NULL_BINARY`/`_ERR_NULL_PLAN`), and a
 *      non-arm64/non-MH_EXECUTE target, a missing `LC_MAIN`, a non-accepted or
 *      mismatched plan, and a zero/out-of-range `target_size` are documented
 *      `Ok(rejected, <reason>)` returns, all guarded in the body.
 * @post `bin`, `plan`, and their borrowed buffers are not modified.
 * @post On accept, `result.ok.cputype == CPU_TYPE_ARM64` and
 *       `result.ok.replacement_entryoff == result.ok.target_file_offset`.
 */
extern n00b_result_t(n00b_macho_rewrite_host_entrypoint_target_t)
n00b_macho_rewrite_plan_host_entrypoint_target(
    n00b_macho_binary_t                *bin,
    n00b_macho_rewrite_loadable_plan_t *plan,
    uint64_t                            target_payload_offset,
    uint64_t                            target_size);

/**
 * @brief Enable a checked LC_MAIN entrypoint patch on a loadable plan.
 *
 * The plan must be accepted, apply-able, and still tied to the binary that
 * produced it with the same original `entryoff`. Records
 * `replacement_entryoff` while preserving `original_entryoff`; apply later
 * writes the replacement into LC_MAIN, reparses the output, and verifies the
 * parsed entrypoint.
 *
 * @param plan Accepted loadable plan.
 * @param replacement_entryoff Concrete LC_MAIN entryoff (file offset) to write.
 * @return Ok(true) when enabled, or Err(N00B_MACHO_REWRITE_ERR_*).
 * @pre (Advisory; D-031.) `plan` is non-null and
 *      `plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED`. These are NOT
 *      trapping preconditions: a null `plan` (`_ERR_NULL_PLAN`) and a
 *      non-accepted plan (`_ERR_PLAN_REJECTED`) are documented `Err` returns
 *      guarded in the body, not a `requires`.
 * @post On success, `plan->entrypoint_patch_enabled` is true.
 * @post On success, `plan->original_entryoff` is unchanged and
 *       `plan->replacement_entryoff == replacement_entryoff`.
 */
extern n00b_result_t(bool)
n00b_macho_rewrite_loadable_plan_enable_entrypoint(
    n00b_macho_rewrite_loadable_plan_t *plan,
    uint64_t                            replacement_entryoff);

// ============================================================================
// Apply functions
// ============================================================================

/**
 * @brief Apply an accepted loadable-segment plan to bytes.
 *
 * The plan must come from @ref n00b_macho_rewrite_plan_loadable_insert for the
 * same parsed binary. Apply grows the load-command region by one
 * LC_SEGMENT_64, relocates __LINKEDIT (and any trailing code signature) when
 * the plan says so, updates every __LINKEDIT-pointing load command
 * (LC_SYMTAB, LC_DYSYMTAB, LC_DYLD_INFO, LC_FUNCTION_STARTS, LC_DATA_IN_CODE,
 * LC_DYLD_CHAINED_FIXUPS, LC_CODE_SIGNATURE), appends the new segment payload,
 * and zero-fills planned padding. Without an enabled entrypoint patch, apply
 * preserves LC_MAIN.entryoff; with one enabled, it writes the replacement and
 * verifies it through the reparsed output. Apply never executes the object and
 * never re-signs (signing reconciliation is WP-011).
 *
 * @param bin Parsed Mach-O object whose stream supplies the original bytes.
 * @param plan Accepted loadable plan.
 * @kw allocator Defaults to `nullptr`; owns the returned output buffer.
 * @return Ok(buffer) of rewritten Mach-O bytes, or Err(N00B_MACHO_REWRITE_ERR_*).
 * @pre `bin`, `bin->stream`, `bin->stream->buf`, and `plan` are non-null. (Advisory; D-031.)
 * @pre `plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED`. (Advisory; D-031.)
 * @pre `plan->source_binary == bin`. (Advisory; D-031 — a mismatched/null/non-accepted
 *      plan is a documented `Err` return guarded in the body, not a trapping precondition.)
 * @post `bin`, its stream buffer, and parsed arrays are not modified.
 *       (no-`old` limit: source-byte non-mutation is test-verified.)
 * @post All original byte ranges outside the planned patch ranges are preserved
 *       in the output. (no-`old` limit: relational, test-verified.)
 * @post The output is at least as large as the input plus the new payload:
 *       `result.ok->byte_len >= bin->stream->buf->byte_len
 *            + plan->payload->byte_len`.
 * @post The returned buffer reparses with @ref n00b_macho_parse_single.
 *       (test-verified — reparse is a function call, illegal in contracts.)
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_loadable_insert_plan(
    n00b_macho_binary_t                *bin,
    n00b_macho_rewrite_loadable_plan_t *plan) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Apply an accepted metadata-insert plan to bytes.
 *
 * @param bin Parsed Mach-O object whose stream supplies the original bytes.
 * @param plan Accepted metadata plan.
 * @kw allocator Defaults to `nullptr`; owns the returned output buffer.
 * @return Ok(buffer) of rewritten Mach-O bytes, or Err(N00B_MACHO_REWRITE_ERR_*).
 * @pre (Advisory; D-031.) `bin`, `bin->stream`, `bin->stream->buf`, and `plan`
 *      are non-null, `plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED`, and
 *      `plan->operation == N00B_MACHO_REWRITE_OPERATION_METADATA_INSERT`. These
 *      are NOT trapping preconditions: a null `bin`/`plan`, a rejected plan, and
 *      a mismatched operation are documented `Err` returns (`_ERR_NULL_BINARY`,
 *      `_ERR_NULL_PLAN`, `_ERR_PLAN_REJECTED`, `_ERR_UNSUPPORTED_PLAN`),
 *      guarded in the body, not a `requires`.
 * @post `bin`, its stream buffer, and parsed arrays are not modified. (no-`old` limit.)
 * @post All original byte ranges outside the planned patch ranges are preserved
 *       in the output. (NFR-01; no-`old` limit: relational, test-verified.)
 * @post `result.ok->byte_len >= bin->stream->buf->byte_len`.
 * @post The returned buffer reparses with @ref n00b_macho_parse_single.
 *       (test-verified — reparse is a function call, illegal in contracts.)
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_metadata_insert_plan(
    n00b_macho_binary_t       *bin,
    n00b_macho_rewrite_plan_t *plan) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Apply an accepted Chalk-mark delete or replace plan to bytes.
 *
 * @param bin Parsed Mach-O object whose stream supplies the original bytes.
 * @param plan Accepted Chalk-mark delete/replace plan.
 * @kw allocator Defaults to `nullptr`; owns the returned output buffer.
 * @return Ok(buffer) of rewritten Mach-O bytes, or Err(N00B_MACHO_REWRITE_ERR_*).
 * @pre `bin`, `bin->stream`, `bin->stream->buf`, and `plan` are non-null.
 * @pre `plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED`.
 * @post `bin`, its stream buffer, and parsed arrays are not modified. (no-`old` limit.)
 * @post `result.ok->byte_len <= bin->stream->buf->byte_len` (replace keeps the
 *        slot size; delete shrinks the file — the rewrite never grows it).
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_chalk_mark_plan(
    n00b_macho_binary_t       *bin,
    n00b_macho_rewrite_plan_t *plan) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Apply an accepted object-bundle insert or replace plan to bytes.
 *
 * @param bin Parsed Mach-O object whose stream supplies the original bytes.
 * @param plan Accepted object-bundle insert/replace plan.
 * @kw allocator Defaults to `nullptr`; owns the returned output buffer.
 * @return Ok(buffer) of rewritten Mach-O bytes, or Err(N00B_MACHO_REWRITE_ERR_*).
 * @pre `bin`, `bin->stream`, `bin->stream->buf`, and `plan` are non-null.
 * @pre `plan->outcome == N00B_MACHO_REWRITE_PLAN_ACCEPTED`.
 * @post `bin`, its stream buffer, and parsed arrays are not modified. (no-`old` limit.)
 * @post `result.ok->byte_len <= bin->stream->buf->byte_len` (object-bundle
 *        replace keeps the slot size — output is the same size, never grows).
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_object_bundle_plan(
    n00b_macho_binary_t       *bin,
    n00b_macho_rewrite_plan_t *plan) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Convenience plan+apply wrappers + profile + helpers
// ============================================================================

/**
 * @brief Plan and apply a metadata insert in one call.
 *
 * @param bin Parsed Mach-O object.
 * @param request Metadata insertion request.
 * @kw allocator Defaults to `nullptr`; owns the returned output buffer.
 * @return Ok(buffer), or Err(N00B_MACHO_REWRITE_ERR_*) (incl. PLAN_REJECTED).
 * @pre `bin`, `request`, `request->note_owner`, and `request->payload` are non-null.
 * @pre `request->payload->byte_len` is nonzero.
 * @post On Ok, `result.ok` is non-null. (no-`old` limit on byte relations.)
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_metadata_insert(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan and apply a Chalk-mark delete in one call.
 *
 * @param bin Parsed Mach-O object.
 * @kw allocator Defaults to `nullptr`; owns the returned output buffer.
 * @return Ok(buffer), or Err(N00B_MACHO_REWRITE_ERR_*) (incl. PLAN_REJECTED).
 * @pre `bin`, `bin->stream`, and `bin->stream->buf` are non-null.
 * @post On Ok, `result.ok` is non-null. (no-`old` limit on byte relations.)
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_chalk_mark_delete(
    n00b_macho_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan and apply an object-bundle delete in one call.
 *
 * Owner-parameterized twin of @ref n00b_macho_rewrite_apply_chalk_mark_delete:
 * plans a bundle-carrier delete (reserved owner `N00B_MACHO_BUNDLE_NOTE_OWNER`)
 * and applies the accepted plan, returning the SMALLER rewritten bytes. Used by
 * the carrier growth-replace composition (delete-then-insert; D-037).
 *
 * @param bin Parsed Mach-O object.
 * @kw allocator Defaults to `nullptr`; owns the returned output buffer.
 * @return Ok(buffer), or Err(N00B_MACHO_REWRITE_ERR_*) (incl. PLAN_REJECTED).
 * @pre (Advisory; D-031.) `bin`, `bin->stream`, and `bin->stream->buf` are
 *      non-null. A null `bin` propagates from the planner as a documented `Err`
 *      return, guarded in the body, not a `requires`.
 * @post On Ok, `result.ok` is non-null. (no-`old` limit on byte relations.)
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_object_bundle_delete(
    n00b_macho_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan and apply a Chalk-mark replace in one call.
 *
 * @param bin Parsed Mach-O object.
 * @param request Metadata replacement request.
 * @kw allocator Defaults to `nullptr`; owns the returned output buffer.
 * @return Ok(buffer), or Err(N00B_MACHO_REWRITE_ERR_*) (incl. PLAN_REJECTED).
 * @pre `bin`, `request`, `request->note_owner`, and `request->payload` are non-null.
 * @pre `request->payload->byte_len` is nonzero.
 * @post On Ok, `result.ok` is non-null. (no-`old` limit on byte relations.)
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_chalk_mark_replace(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan and apply an object-bundle insert in one call.
 *
 * @param bin Parsed Mach-O object.
 * @param request Metadata insertion request.
 * @kw allocator Defaults to `nullptr`; owns the returned output buffer.
 * @return Ok(buffer), or Err(N00B_MACHO_REWRITE_ERR_*) (incl. PLAN_REJECTED).
 * @pre `bin`, `request`, `request->note_owner`, and `request->payload` are non-null.
 * @pre `request->payload->byte_len` is nonzero.
 * @post On Ok, `result.ok` is non-null. (no-`old` limit on byte relations.)
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_object_bundle_insert(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan and apply an object-bundle replace in one call.
 *
 * @param bin Parsed Mach-O object.
 * @param request Metadata replacement request.
 * @kw allocator Defaults to `nullptr`; owns the returned output buffer.
 * @return Ok(buffer), or Err(N00B_MACHO_REWRITE_ERR_*) (incl. PLAN_REJECTED).
 * @pre `bin`, `request`, `request->note_owner`, and `request->payload` are non-null.
 * @pre `request->payload->byte_len` is nonzero.
 * @post On Ok, `result.ok` is non-null. (no-`old` limit on byte relations.)
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_macho_rewrite_apply_object_bundle_replace(
    n00b_macho_binary_t                   *bin,
    n00b_macho_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Evaluate the packager-compatible target shape of a Mach-O object.
 *
 * Read-only. Reports whether the object is a single-slice arm64 Mach-O with a
 * well-formed load-command region, a trailing `__LINKEDIT`, and (if present) a
 * trailing code signature — the shape the rewrite layer requires.
 *
 * @param bin Parsed Mach-O object.
 * @return Ok(profile) or Err(N00B_MACHO_REWRITE_ERR_*).
 * @pre (Advisory; D-031.) `bin` and `bin->stream` are non-null. This is NOT a
 *      trapping precondition: a null `bin`/`bin->stream` is a documented `Err`
 *      return (`_ERR_NULL_BINARY`), guarded in the body, not a `requires`.
 * @post `result.ok` describes the shape; `reason == N00B_MACHO_REWRITE_PROFILE_OK`
 *       iff the object is rewrite-compatible.
 */
extern n00b_result_t(n00b_macho_rewrite_target_profile_t)
n00b_macho_rewrite_target_profile(n00b_macho_binary_t *bin);

/**
 * @brief Look up a human-readable string for an `N00B_MACHO_REWRITE_ERR_*` code.
 *
 * @param err Error code returned by the Mach-O rewrite API.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_rewrite_err_str(n00b_err_t err);

/**
 * @brief Look up a stable name for a Mach-O rewrite plan outcome.
 *
 * @param outcome Plan-outcome value.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_rewrite_plan_outcome_str(
    n00b_macho_rewrite_plan_outcome_t outcome);

/**
 * @brief Look up a stable name for a Mach-O rewrite rejection reason.
 *
 * @param reason Rejection-reason value.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_rewrite_rejection_reason_str(
    n00b_macho_rewrite_rejection_reason_t reason);

/**
 * @brief Look up a stable name for a Mach-O rewrite target-profile reason.
 *
 * @param reason Target-profile-reason value.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_rewrite_target_profile_reason_str(
    n00b_macho_rewrite_target_profile_reason_t reason);

/**
 * @brief Look up a stable name for a Mach-O rewrite patch kind.
 *
 * @param kind Patch-kind value.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_rewrite_patch_kind_str(
    n00b_macho_rewrite_patch_kind_t kind);

/**
 * @brief Look up a stable name for an arm64 host-entrypoint rejection reason.
 *
 * @param reason Host-entrypoint rejection-reason value.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_rewrite_host_entrypoint_rejection_reason_str(
    n00b_macho_rewrite_host_entrypoint_rejection_reason_t reason);
