/**
 * @file elf_rewrite.h
 * @brief Surgical ELF rewrite planning and apply API.
 *
 * This layer turns strict rewrite admission facts into explicit patch plans,
 * then applies accepted plans to new in-memory byte buffers. Planning and
 * application never mutate the parsed ELF object or its original byte stream.
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
#include "compiler/objfile/elf.h"
#include "compiler/objfile/elf_rewrite_admit.h"

#define N00B_ELF_REWRITE_OK 0
#define N00B_ELF_REWRITE_ERR_NULL_BINARY       (-3601)
#define N00B_ELF_REWRITE_ERR_NULL_REQUEST      (-3602)
#define N00B_ELF_REWRITE_ERR_NULL_SECTION_NAME (-3603)
#define N00B_ELF_REWRITE_ERR_NULL_PAYLOAD      (-3604)
#define N00B_ELF_REWRITE_ERR_ZERO_PAYLOAD_SIZE (-3605)
#define N00B_ELF_REWRITE_ERR_TARGET_PROFILE    (-3606)
#define N00B_ELF_REWRITE_ERR_ADMISSION         (-3607)
#define N00B_ELF_REWRITE_ERR_OVERFLOW          (-3608)
#define N00B_ELF_REWRITE_ERR_NULL_PLAN         (-3609)
#define N00B_ELF_REWRITE_ERR_PLAN_REJECTED     (-3610)
#define N00B_ELF_REWRITE_ERR_UNSUPPORTED_PLAN  (-3611)
#define N00B_ELF_REWRITE_ERR_APPLY             (-3612)
#define N00B_ELF_REWRITE_ERR_PARSE_AFTER_APPLY (-3613)
#define N00B_ELF_REWRITE_ERR_MARK_NOT_FOUND    (-3614)
#define N00B_ELF_REWRITE_ERR_TRUSTED_NAME      (-3615)

typedef enum {
    N00B_ELF_REWRITE_PLAN_ACCEPTED,
    N00B_ELF_REWRITE_PLAN_REJECTED,
} n00b_elf_rewrite_plan_outcome_t;

typedef enum {
    N00B_ELF_REWRITE_OPERATION_METADATA_INSERT,
    N00B_ELF_REWRITE_OPERATION_CHALK_MARK_DELETE,
    N00B_ELF_REWRITE_OPERATION_CHALK_MARK_REPLACE,
    N00B_ELF_REWRITE_OPERATION_OBJECT_BUNDLE_REPLACE,
    N00B_ELF_REWRITE_OPERATION_LOADABLE_INSERT,
} n00b_elf_rewrite_operation_t;

typedef enum {
    N00B_ELF_REWRITE_REJECT_NONE,
    N00B_ELF_REWRITE_REJECT_TARGET_PROFILE,
    N00B_ELF_REWRITE_REJECT_ADMISSION,
    N00B_ELF_REWRITE_REJECT_TABLE_PLACEMENT,
    N00B_ELF_REWRITE_REJECT_SECTION_COUNT_PROMOTION,
    N00B_ELF_REWRITE_REJECT_OVERFLOW,
    N00B_ELF_REWRITE_REJECT_CHALK_MARK_NOT_FOUND,
    N00B_ELF_REWRITE_REJECT_CHALK_MARK_UNSUPPORTED,
    N00B_ELF_REWRITE_REJECT_TRUSTED_NAME,
    N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_NOT_FOUND,
    N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_DUPLICATE,
    N00B_ELF_REWRITE_REJECT_OBJECT_BUNDLE_UNSUPPORTED,
    N00B_ELF_REWRITE_REJECT_LOADABLE_PLACEMENT,
    N00B_ELF_REWRITE_REJECT_LOADABLE_ADDRESS,
} n00b_elf_rewrite_rejection_reason_t;

typedef enum {
    N00B_ELF_REWRITE_PROFILE_OK,
    N00B_ELF_REWRITE_PROFILE_INVALID_EHSIZE,
    N00B_ELF_REWRITE_PROFILE_INVALID_SHENTSIZE,
    N00B_ELF_REWRITE_PROFILE_INVALID_PHENTSIZE,
    N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_SHNLO,
    N00B_ELF_REWRITE_PROFILE_SHTAB_SIZE,
    N00B_ELF_REWRITE_PROFILE_INVALID_SHTAB_BOUNDS,
    N00B_ELF_REWRITE_PROFILE_ZERO_PHNUM,
    N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_PXNUM,
    N00B_ELF_REWRITE_PROFILE_INVALID_PHTAB,
    N00B_ELF_REWRITE_PROFILE_INVALID_PHTAB_BOUNDS,
    N00B_ELF_REWRITE_PROFILE_NO_STRTAB,
    N00B_ELF_REWRITE_PROFILE_STRTAB_SIZE_WRAP,
    N00B_ELF_REWRITE_PROFILE_UNSUPPORTED_STRTAB_SHNLO,
    N00B_ELF_REWRITE_PROFILE_INVALID_STRTAB_INDEX,
    N00B_ELF_REWRITE_PROFILE_INVALID_STRTAB_TYPE,
    N00B_ELF_REWRITE_PROFILE_STRTAB_SIZE,
    N00B_ELF_REWRITE_PROFILE_SECTION_NAME_INDEX,
} n00b_elf_rewrite_target_profile_reason_t;

typedef enum {
    N00B_ELF_REWRITE_TABLE_STRATEGY_NONE,
    N00B_ELF_REWRITE_TABLE_STRATEGY_IN_PLACE_SHSTRTAB_GROWTH,
    N00B_ELF_REWRITE_TABLE_STRATEGY_TERMINAL_TAIL_INCISION,
    N00B_ELF_REWRITE_TABLE_STRATEGY_EOF_REPLACEMENT,
    N00B_ELF_REWRITE_TABLE_STRATEGY_AFTER_OVERLAY_REPLACEMENT,
} n00b_elf_rewrite_table_strategy_t;

typedef enum {
    N00B_ELF_REWRITE_PATCH_ELF_HEADER,
    N00B_ELF_REWRITE_PATCH_PAYLOAD,
    N00B_ELF_REWRITE_PATCH_SECTION_NAME_STRTAB,
    N00B_ELF_REWRITE_PATCH_SECTION_HEADER_TABLE,
    N00B_ELF_REWRITE_PATCH_TABLE_TAIL,
    N00B_ELF_REWRITE_PATCH_APPENDED_TABLES,
    N00B_ELF_REWRITE_PATCH_STALE_PAYLOAD,
    N00B_ELF_REWRITE_PATCH_ADJUSTED_PHTAB,
    N00B_ELF_REWRITE_PATCH_ADJUSTED_PT_PHDR,
    N00B_ELF_REWRITE_PATCH_LOADABLE_PADDING,
    N00B_ELF_REWRITE_PATCH_RELOCATED_PHTAB,
    N00B_ELF_REWRITE_PATCH_RELOCATED_PT_PHDR,
    N00B_ELF_REWRITE_PATCH_NEW_PT_LOAD,
    N00B_ELF_REWRITE_PATCH_LOADABLE_PAYLOAD,
} n00b_elf_rewrite_patch_kind_t;

typedef enum {
    N00B_ELF_REWRITE_LOADABLE_RELOCATION_NONE,
    N00B_ELF_REWRITE_LOADABLE_RELOCATION_ACCEPTED,
    N00B_ELF_REWRITE_LOADABLE_RELOCATION_REJECTED,
} n00b_elf_rewrite_loadable_relocation_status_t;

typedef struct n00b_elf_rewrite_metadata_request {
    n00b_string_t                  *section_name;
    n00b_buffer_t                  *payload;
    uint64_t                        file_alignment;
    uint32_t                        section_type;
    uint64_t                        section_flags;
    n00b_option_t(uint64_t)         preferred_file_offset;
    n00b_elf_rewrite_admit_policy_t policy;
} n00b_elf_rewrite_metadata_request_t;

/**
 * @brief Byte-bearing request for planning one ELF64 `PT_LOAD`.
 *
 * The request borrows `payload`; callers retain ownership. Planning validates
 * generic segment facts and either leaves placement deferred or records the
 * concrete in-place / relocated PHTAB and payload facts needed by apply.
 */
typedef struct n00b_elf_rewrite_loadable_request {
    n00b_buffer_t                                *payload;
    uint32_t                                      segment_flags;
    uint64_t                                      file_alignment;
    uint64_t                                      vaddr_alignment;
    uint64_t                                      p_memsz;
    n00b_elf_rewrite_loadable_phtab_strategy_t   phtab_strategy;
    n00b_elf_rewrite_admit_policy_t              policy;
} n00b_elf_rewrite_loadable_request_t;

typedef struct n00b_elf_rewrite_target_profile {
    n00b_elf_rewrite_target_profile_reason_t reason;
    int                                      packager_errcode;
    bool                                     shstrtab_requires_terminator;
    uint64_t                                 file_size;
    uint64_t                                 section_count;
    uint64_t                                 segment_count;
    uint64_t                                 shstrtab_offset;
    uint64_t                                 shstrtab_reported_size;
    uint64_t                                 shstrtab_complete_size;
} n00b_elf_rewrite_target_profile_t;

typedef struct n00b_elf_rewrite_patch {
    n00b_elf_rewrite_patch_kind_t kind;
    uint64_t                      file_offset;
    uint64_t                      file_end;
    uint64_t                      original_file_offset;
    uint64_t                      original_file_end;
} n00b_elf_rewrite_patch_t;

/**
 * @brief Relocated-PHTAB loadable planning facts.
 *
 * Accepted facts describe the future live PHTAB, header update, updated
 * `PT_PHDR`, appended `PT_LOAD`, and payload placement. They are not apply
 * instructions by themselves; top-level changed byte ranges are carried in the
 * loadable plan's patch array.
 */
typedef struct n00b_elf_rewrite_loadable_relocation {
    n00b_elf_rewrite_loadable_relocation_status_t status;
    n00b_elf_rewrite_rejection_reason_t           rejection_reason;
    n00b_elf_rewrite_admit_rejection_reason_t     source_in_place_rejection;
    uint64_t                                      elf_header_patch_offset;
    uint64_t                                      elf_header_patch_end;
    uint64_t                                      elf_header_new_phoff;
    uint64_t                                      elf_header_new_phnum;
    uint64_t                                      elf_header_entry;
    uint64_t                                      original_phtab_offset;
    uint64_t                                      original_phtab_size;
    uint64_t                                      original_phtab_end;
    uint64_t                                      original_phtab_vaddr;
    uint64_t                                      relocated_phtab_offset;
    uint64_t                                      relocated_phtab_size;
    uint64_t                                      relocated_phtab_end;
    uint64_t                                      relocated_phtab_vaddr;
    uint64_t                                      relocated_phtab_vaddr_end;
    bool                                          pt_phdr_present;
    uint32_t                                      pt_phdr_index;
    uint64_t                                      pt_phdr_entry_offset;
    uint64_t                                      pt_phdr_new_offset;
    uint64_t                                      pt_phdr_new_filesz;
    uint64_t                                      pt_phdr_new_memsz;
    uint64_t                                      pt_phdr_new_vaddr;
    uint64_t                                      pt_phdr_new_paddr;
    uint32_t                                      new_pt_load_index;
    uint64_t                                      new_pt_load_entry_offset;
    uint64_t                                      new_pt_load_offset;
    uint64_t                                      new_pt_load_vaddr;
    uint64_t                                      new_pt_load_paddr;
    uint64_t                                      new_pt_load_filesz;
    uint64_t                                      new_pt_load_memsz;
    uint32_t                                      new_pt_load_flags;
    uint64_t                                      new_pt_load_align;
    uint64_t                                      payload_offset;
    uint64_t                                      payload_end;
    uint64_t                                      payload_vaddr;
    uint64_t                                      payload_vaddr_end;
} n00b_elf_rewrite_loadable_relocation_t;

typedef struct n00b_elf_rewrite_plan {
    n00b_elf_rewrite_operation_t                 operation;
    n00b_elf_rewrite_plan_outcome_t             outcome;
    n00b_elf_rewrite_rejection_reason_t         rejection_reason;
    n00b_elf_rewrite_target_profile_t           target_profile;
    n00b_elf_rewrite_admit_result_t             admission;
    n00b_elf_rewrite_table_strategy_t           table_strategy;
    n00b_array_t(n00b_elf_rewrite_patch_t)      patches;
    n00b_string_t                              *section_name;
    n00b_buffer_t                              *payload;
    uint64_t                                    section_alignment;
    uint32_t                                    section_type;
    uint64_t                                    section_flags;
    uint64_t                                    file_size;
    uint64_t                                    original_section_count;
    uint64_t                                    new_section_count;
    uint64_t                                    removed_section_index;
    uint64_t                                    removed_payload_offset;
    uint64_t                                    removed_payload_end;
    uint16_t                                    new_shstrndx;
    uint64_t                                    payload_offset;
    uint64_t                                    payload_end;
} n00b_elf_rewrite_plan_t;

/**
 * @brief Loadable-segment rewrite plan.
 *
 * Accepted deferred plans carry validation facts only. Accepted in-place PHTAB
 * adjustment and relocated-PHTAB plans carry concrete, non-overlapping patch
 * ranges and are consumable by @ref n00b_elf_rewrite_apply_loadable_insert_plan.
 * Plans borrow the parsed binary that produced them so apply can enforce the
 * same-binary precondition. They record the original `e_entry`; entrypoint
 * patch facts are disabled by default and may be enabled on apply-able
 * accepted plans once a caller has concrete target entrypoint facts.
 */
typedef struct n00b_elf_rewrite_loadable_plan {
    n00b_elf_rewrite_plan_outcome_t              outcome;
    n00b_elf_rewrite_rejection_reason_t          rejection_reason;
    n00b_elf_rewrite_target_profile_t            target_profile;
    n00b_elf_rewrite_admit_loadable_result_t     admission;
    n00b_array_t(n00b_elf_rewrite_patch_t)        patches;
    n00b_elf_rewrite_loadable_phtab_strategy_t   phtab_strategy;
    n00b_elf_rewrite_loadable_placement_t        payload_placement;
    n00b_elf_rewrite_loadable_placement_t        phtab_placement;
    n00b_elf_rewrite_loadable_phtab_adjustment_t phtab_adjustment;
    n00b_elf_rewrite_loadable_relocation_t       phtab_relocation;
    n00b_elf_binary_t                            *source_binary;
    n00b_buffer_t                               *payload;
    uint64_t                                     original_entrypoint;
    uint64_t                                     replacement_entrypoint;
    uint64_t                                     file_size;
    uint64_t                                     original_segment_count;
    uint64_t                                     new_segment_count;
    uint64_t                                     p_memsz;
    uint64_t                                     file_alignment;
    uint64_t                                     vaddr_alignment;
    uint32_t                                     segment_flags;
    bool                                         entrypoint_policy_deferred;
    bool                                         entrypoint_patch_enabled;
} n00b_elf_rewrite_loadable_plan_t;

typedef enum {
    N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_NONE,
    N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_PLAN,
    N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_PLAN,
    N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_CLASS,
    N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_ENDIAN,
    N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_UNSUPPORTED_MACHINE,
    N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_NON_EXECUTABLE,
    N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_TARGET_OUT_OF_RANGE,
    N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_TARGET_MEMORY_ONLY,
    N00B_ELF_REWRITE_HOST_ENTRYPOINT_REJECT_OVERFLOW,
} n00b_elf_rewrite_host_entrypoint_rejection_reason_t;

/**
 * @brief Static host-entrypoint target-policy facts for one loadable plan.
 *
 * Accepted facts describe direct `e_entry` redirection to a byte range within
 * the newly inserted file-backed `PT_LOAD` payload. WP-016 currently emits no
 * trampoline bytes, so accepted results set `trampoline_emitted == false` and
 * `trampoline_size == 0`.
 */
typedef struct n00b_elf_rewrite_host_entrypoint_target {
    n00b_elf_rewrite_plan_outcome_t                         outcome;
    n00b_elf_rewrite_host_entrypoint_rejection_reason_t      rejection_reason;
    uint64_t                                                 original_entrypoint;
    uint64_t                                                 replacement_entrypoint;
    uint64_t                                                 target_payload_offset;
    uint64_t                                                 target_size;
    uint64_t                                                 target_file_offset;
    uint64_t                                                 target_file_end;
    uint64_t                                                 target_vaddr;
    uint64_t                                                 target_vaddr_end;
    uint64_t                                                 payload_file_offset;
    uint64_t                                                 payload_file_end;
    uint64_t                                                 payload_vaddr;
    uint64_t                                                 payload_vaddr_end;
    uint64_t                                                 payload_file_size;
    uint64_t                                                 payload_memory_size;
    bool                                                     trampoline_emitted;
    uint64_t                                                 trampoline_size;
} n00b_elf_rewrite_host_entrypoint_target_t;

/**
 * @brief Plan insertion of a non-loadable ELF metadata section.
 *
 * The request borrows `section_name` and `payload`; callers retain ownership.
 * Accepted plans describe the changed file ranges but do not perform those
 * writes. Rejected plans use stable N00b-owned reasons and, where applicable,
 * target-profile facts that map to Brandon packager's `read-target` behavior.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @param request Metadata-section insertion request.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *               Owns the returned plan and patch array.
 *
 * @return Ok(plan) for accepted or rejected plans, or Err(N00B_ELF_REWRITE_ERR_*).
 *
 * @pre `bin`, `request`, `request->section_name`, and `request->payload` are non-null.
 * @pre `request->payload->byte_len` is nonzero.
 * @post `bin`, its stream, and its parsed section and segment arrays are not modified.
 */
extern n00b_result_t(n00b_elf_rewrite_plan_t *)
n00b_elf_rewrite_plan_metadata_insert(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan trusted insertion of Chalk's exact `.chalk.mark` section.
 *
 * This is the narrow reserved-name affordance needed by Chalk. It admits only
 * an exact `.chalk.mark` request for non-loadable metadata insertion; any other
 * requested name is rejected. The ordinary
 * @ref n00b_elf_rewrite_plan_metadata_insert path continues to reject
 * `.chalk.mark`, arbitrary `.chalk.*`, `.0c001.*`, and targets with existing
 * reserved metadata sections.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @param request Metadata-section insertion request whose name is exactly
 *                `.chalk.mark`.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *
 * @return Ok(plan) for accepted or rejected plans, or Err(N00B_ELF_REWRITE_ERR_*).
 *
 * @pre `bin`, `request`, `request->section_name`, and `request->payload` are non-null.
 * @pre `request->payload->byte_len` is nonzero.
 * @post `bin`, its stream, and its parsed section and segment arrays are not modified.
 */
extern n00b_result_t(n00b_elf_rewrite_plan_t *)
n00b_elf_rewrite_plan_chalk_mark_insert(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan trusted insertion of N00b's exact `.0c001.bundle` section.
 *
 * This is the narrow N00b binary-section affordance needed by the future
 * object-bundle writer. It admits only an exact `.0c001.bundle` request as
 * non-loadable `SHT_PROGBITS` with `section_flags == 0`; any other requested
 * name or section shape is rejected. The ordinary
 * @ref n00b_elf_rewrite_plan_metadata_insert path continues to reject
 * `.0c001.bundle` and all other `.0c001.*` names. Existing non-conflicting
 * `.chalk.mark` and `.chalk.free` sections are preserved by the trusted
 * object-bundle path.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @param request Metadata-section insertion request whose name is exactly
 *                `.0c001.bundle`.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *
 * @return Ok(plan) for accepted or rejected plans, or Err(N00B_ELF_REWRITE_ERR_*).
 *
 * @pre `bin`, `request`, `request->section_name`, and `request->payload` are non-null.
 * @pre `request->payload->byte_len` is nonzero.
 * @post `bin`, its stream, and its parsed section and segment arrays are not modified.
 */
extern n00b_result_t(n00b_elf_rewrite_plan_t *)
n00b_elf_rewrite_plan_object_bundle_insert(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan surgical deletion of one live non-loadable `.chalk.mark`.
 *
 * Accepted plans append replacement section-name and section-header tables,
 * update the ELF header to point at them, and mark the old mark payload range
 * as `N00B_ELF_REWRITE_PATCH_STALE_PAYLOAD` so application can zero it.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *
 * @return Ok(plan) for accepted or rejected plans, or Err(N00B_ELF_REWRITE_ERR_*).
 *
 * @pre `bin`, `bin->stream`, and `bin->stream->buf` are non-null.
 * @post `bin`, its stream, and its parsed section and segment arrays are not modified.
 */
extern n00b_result_t(n00b_elf_rewrite_plan_t *)
n00b_elf_rewrite_plan_chalk_mark_delete(
    n00b_elf_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan surgical replacement of one live non-loadable `.chalk.mark`.
 *
 * Replacement removes the old live section table entry, excludes the old
 * payload bytes by zeroing their range at apply time, and emits exactly one
 * live `.chalk.mark` entry for the supplied payload.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @param request Replacement request whose section name is exactly `.chalk.mark`.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *
 * @return Ok(plan) for accepted or rejected plans, or Err(N00B_ELF_REWRITE_ERR_*).
 *
 * @pre `bin`, `request`, `request->section_name`, and `request->payload` are non-null.
 * @pre `request->payload->byte_len` is nonzero.
 * @post `bin`, its stream, and its parsed section and segment arrays are not modified.
 */
extern n00b_result_t(n00b_elf_rewrite_plan_t *)
n00b_elf_rewrite_plan_chalk_mark_replace(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan surgical replacement of one live `.0c001.bundle` section.
 *
 * Replacement removes exactly one valid existing non-loadable `SHT_PROGBITS`
 * `.0c001.bundle`, excludes its old payload bytes by zeroing their range at
 * apply time, and emits exactly one replacement `.0c001.bundle` entry for the
 * supplied payload. Missing, duplicate, malformed, or overlapping existing
 * carriers are rejected.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @param request Replacement request whose section name is exactly
 *                `.0c001.bundle`.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *
 * @return Ok(plan) for accepted or rejected plans, or Err(N00B_ELF_REWRITE_ERR_*).
 *
 * @pre `bin`, `request`, `request->section_name`, and `request->payload` are non-null.
 * @pre `request->payload->byte_len` is nonzero.
 * @post `bin`, its stream, and its parsed section and segment arrays are not modified.
 */
extern n00b_result_t(n00b_elf_rewrite_plan_t *)
n00b_elf_rewrite_plan_object_bundle_replace(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Plan insertion of one ELF64 loadable segment without emitting bytes.
 *
 * Accepted plans expose stable facts for request validation, target profile,
 * PHTAB strategy, segment count, payload placement, PHTAB placement, concrete
 * patch ranges for in-place / relocated PHTAB strategies, and deferred generic
 * entrypoint policy. Deferred-strategy plans are validation-only and are not
 * accepted by apply.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @param request Loadable-segment insertion request.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *               Owns the returned plan.
 *
 * @return Ok(plan) for accepted or rejected plans, or Err(N00B_ELF_REWRITE_ERR_*).
 *
 * @pre `bin`, `request`, and `request->payload` are non-null.
 * @pre `request->payload->byte_len` is nonzero.
 * @post `bin`, its stream, and its parsed section and segment arrays are not modified.
 */
extern n00b_result_t(n00b_elf_rewrite_loadable_plan_t *)
n00b_elf_rewrite_plan_loadable_insert(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_loadable_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Validate static ELF host-entrypoint redirection policy.
 *
 * The helper is manifest-agnostic and object-bundle-agnostic. It accepts only
 * apply-able loadable insertion plans for ELF64 little-endian x86-64 and a
 * caller-selected target range expressed as an offset within the planned
 * loadable payload bytes. Accepted results derive the concrete replacement
 * `e_entry` value from the plan's final `PT_LOAD` placement facts and can be
 * passed to @ref n00b_elf_rewrite_loadable_plan_enable_entrypoint.
 *
 * @param bin Parsed ELF object used to produce `plan`.
 * @param plan Accepted in-place or relocated loadable plan.
 * @param target_payload_offset Start of the selected target within
 *                              `plan->payload`.
 * @param target_size Size in bytes of the selected target range.
 *
 * @return Ok(target facts) for accepted or rejected policy decisions, or
 *         Err(N00B_ELF_REWRITE_ERR_*) for null inputs.
 *
 * @pre `bin` and `plan` are non-null.
 * @post `bin`, `plan`, and their borrowed byte buffers are not modified.
 */
extern n00b_result_t(n00b_elf_rewrite_host_entrypoint_target_t)
n00b_elf_rewrite_plan_host_entrypoint_target(
    n00b_elf_binary_t                  *bin,
    n00b_elf_rewrite_loadable_plan_t   *plan,
    uint64_t                            target_payload_offset,
    uint64_t                            target_size);

/**
 * @brief Enable a checked ELF header entrypoint patch on a loadable plan.
 *
 * The plan must be accepted, apply-able, and still tied to the parsed binary
 * that produced it with the same original `e_entry`. This helper records
 * `replacement_entrypoint` while preserving `original_entrypoint`; apply later
 * writes the replacement into `e_entry`, reparses the output, and verifies the
 * parsed entrypoint. It does not inspect architecture, object-bundle
 * manifests, selectors, or policy.
 *
 * @param plan Accepted in-place or relocated loadable plan.
 * @param replacement_entrypoint Concrete ELF64 `e_entry` value to write.
 *
 * @return Ok(true) when the plan is enabled, or Err(N00B_ELF_REWRITE_ERR_*).
 *
 * @pre `plan` is non-null.
 * @pre `plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED`.
 * @pre `plan` has concrete loadable/PHTAB placement facts accepted by apply.
 * @post `plan->entrypoint_patch_enabled` is true on success.
 * @post `plan->original_entrypoint` remains the source binary's original
 *       `e_entry`, and `plan->replacement_entrypoint` is the supplied value.
 */
extern n00b_result_t(bool)
n00b_elf_rewrite_loadable_plan_enable_entrypoint(
    n00b_elf_rewrite_loadable_plan_t *plan,
    uint64_t                          replacement_entrypoint);

/**
 * @brief Apply an accepted loadable-segment rewrite plan to bytes.
 *
 * The plan must come from @ref n00b_elf_rewrite_plan_loadable_insert for the
 * same parsed binary. Accepted in-place PHTAB-adjustment plans move the live
 * PHTAB to the planned adjusted offset, update `e_phoff` / `e_phnum`, update
 * the copied `PT_PHDR`, extend the containing `PT_LOAD`, append one new
 * `PT_LOAD`, and write the payload bytes. Accepted relocated-PHTAB plans write
 * the relocated live PHTAB, leave the original PHTAB bytes as shadow bytes,
 * update `PT_PHDR`, append the new `PT_LOAD`, zero planned padding, and write
 * the payload bytes. Without an enabled entrypoint patch, apply preserves the
 * source header `e_entry`. When
 * @ref n00b_elf_rewrite_loadable_plan_enable_entrypoint has enabled an
 * entrypoint patch, apply also writes the planned replacement `e_entry` value
 * and verifies it through the reparsed output. Applying a plan never executes
 * the rewritten object.
 *
 * @param bin Parsed ELF object whose stream supplies the original bytes.
 * @param plan Accepted loadable plan.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *               Owns the returned output buffer.
 *
 * @return Ok(buffer) containing the rewritten ELF bytes, or
 *         Err(N00B_ELF_REWRITE_ERR_*).
 *
 * @pre `bin`, `bin->stream`, `bin->stream->buf`, and `plan` are non-null.
 * @pre `plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED`.
 * @pre `plan` still matches @p bin and its recorded original `e_entry`.
 * @post `bin`, its stream buffer, and parsed arrays are not modified.
 * @post The returned buffer reparses successfully with @ref n00b_elf_parse.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_loadable_insert_plan(
    n00b_elf_binary_t                  *bin,
    n00b_elf_rewrite_loadable_plan_t   *plan) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Apply an accepted metadata-insert rewrite plan to bytes.
 *
 * The plan must come from @ref n00b_elf_rewrite_plan_metadata_insert or
 * @ref n00b_elf_rewrite_plan_chalk_mark_insert or
 * @ref n00b_elf_rewrite_plan_object_bundle_insert for the same parsed binary.
 * Accepted plans borrow the metadata name, payload, type, flags, and alignment
 * from the original request so this plan-first API does not need the request
 * again.
 *
 * Accepted plans may place metadata payload bytes at EOF, in an admitted
 * zero-padding file gap, or after a preserved overlay when policy permits
 * appending there. Overlay-bearing inputs are applied only for plans whose
 * table strategy appends replacement metadata tables after the overlay.
 *
 * @param bin Parsed ELF object whose stream supplies the original bytes.
 * @param plan Accepted metadata-insert plan.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *               Owns the returned output buffer.
 *
 * @return Ok(buffer) containing the rewritten ELF bytes, or
 *         Err(N00B_ELF_REWRITE_ERR_*).
 *
 * @pre `bin`, `bin->stream`, `bin->stream->buf`, and `plan` are non-null.
 * @pre `plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED`.
 * @post `bin`, its stream buffer, and parsed arrays are not modified.
 * @post The returned buffer reparses successfully with @ref n00b_elf_parse.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_metadata_insert_plan(
    n00b_elf_binary_t         *bin,
    n00b_elf_rewrite_plan_t   *plan) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Apply an accepted Chalk mark delete or replace plan to bytes.
 *
 * @param bin Parsed ELF object whose stream supplies the original bytes.
 * @param plan Accepted plan from @ref n00b_elf_rewrite_plan_chalk_mark_delete
 *             or @ref n00b_elf_rewrite_plan_chalk_mark_replace.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *
 * @return Ok(buffer) containing the rewritten ELF bytes, or
 *         Err(N00B_ELF_REWRITE_ERR_*).
 *
 * @pre `bin`, `bin->stream`, `bin->stream->buf`, and `plan` are non-null.
 * @pre `plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED`.
 * @post The returned buffer reparses successfully with @ref n00b_elf_parse.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_chalk_mark_plan(
    n00b_elf_binary_t       *bin,
    n00b_elf_rewrite_plan_t *plan) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Apply an accepted `.0c001.bundle` insert or replace plan to bytes.
 *
 * @param bin Parsed ELF object whose stream supplies the original bytes.
 * @param plan Accepted plan from @ref n00b_elf_rewrite_plan_object_bundle_insert
 *             or @ref n00b_elf_rewrite_plan_object_bundle_replace.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *
 * @return Ok(buffer) containing the rewritten ELF bytes, or
 *         Err(N00B_ELF_REWRITE_ERR_*).
 *
 * @pre `bin`, `bin->stream`, `bin->stream->buf`, and `plan` are non-null.
 * @pre `plan->outcome == N00B_ELF_REWRITE_PLAN_ACCEPTED`.
 * @post The returned buffer reparses successfully with @ref n00b_elf_parse.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_object_bundle_plan(
    n00b_elf_binary_t       *bin,
    n00b_elf_rewrite_plan_t *plan) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Convenience wrapper that plans and applies a metadata insertion.
 *
 * This is a request-level shortcut over
 * @ref n00b_elf_rewrite_plan_metadata_insert and
 * @ref n00b_elf_rewrite_apply_metadata_insert_plan. Callers that need to
 * inspect planned changed ranges should use the plan-first API directly.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @param request Metadata-section insertion request.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *
 * @return Ok(buffer), Err(N00B_ELF_REWRITE_ERR_*), or
 *         Err(N00B_ELF_REWRITE_ERR_PLAN_REJECTED) when admission/planning
 *         returns a rejected plan.
 *
 * @post `bin`, its stream buffer, and parsed arrays are not modified.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_metadata_insert(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Convenience wrapper that plans and applies `.chalk.mark` deletion.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *
 * @return Ok(buffer), Err(N00B_ELF_REWRITE_ERR_*), or
 *         Err(N00B_ELF_REWRITE_ERR_PLAN_REJECTED) when planning rejects.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_chalk_mark_delete(
    n00b_elf_binary_t *bin) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Convenience wrapper that plans and applies `.chalk.mark` replacement.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @param request Replacement request whose section name is exactly `.chalk.mark`.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *
 * @return Ok(buffer), Err(N00B_ELF_REWRITE_ERR_*), or
 *         Err(N00B_ELF_REWRITE_ERR_PLAN_REJECTED) when planning rejects.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_chalk_mark_replace(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Convenience wrapper that plans and applies `.0c001.bundle` insertion.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @param request Insert request whose section name is exactly `.0c001.bundle`.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *
 * @return Ok(buffer), Err(N00B_ELF_REWRITE_ERR_*), or
 *         Err(N00B_ELF_REWRITE_ERR_PLAN_REJECTED) when planning rejects.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_object_bundle_insert(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Convenience wrapper that plans and applies `.0c001.bundle` replacement.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @param request Replacement request whose section name is exactly
 *                `.0c001.bundle`.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *
 * @return Ok(buffer), Err(N00B_ELF_REWRITE_ERR_*), or
 *         Err(N00B_ELF_REWRITE_ERR_PLAN_REJECTED) when planning rejects.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_elf_rewrite_apply_object_bundle_replace(
    n00b_elf_binary_t                   *bin,
    n00b_elf_rewrite_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Evaluate packager-compatible rewrite target semantics.
 *
 * This is stricter than parsing and inspects raw section-header bytes where
 * parsed names have already been normalized.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @return Ok(profile) or Err(N00B_ELF_REWRITE_ERR_*).
 *
 * @post `bin` and its stream position are not modified.
 */
extern n00b_result_t(n00b_elf_rewrite_target_profile_t)
n00b_elf_rewrite_target_profile(n00b_elf_binary_t *bin);

/**
 * @param err ELF rewrite error code.
 * @return Stable process-lifetime diagnostic string.
 */
extern n00b_string_t *n00b_elf_rewrite_err_str(n00b_err_t err);

/**
 * @param outcome Metadata rewrite plan outcome.
 * @return Stable process-lifetime enum-name string.
 */
extern n00b_string_t *n00b_elf_rewrite_plan_outcome_str(
    n00b_elf_rewrite_plan_outcome_t outcome);

/**
 * @param reason Metadata rewrite rejection reason.
 * @return Stable process-lifetime enum-name string.
 */
extern n00b_string_t *n00b_elf_rewrite_rejection_reason_str(
    n00b_elf_rewrite_rejection_reason_t reason);

/**
 * @param reason Target profile rejection reason.
 * @return Stable process-lifetime enum-name string.
 */
extern n00b_string_t *n00b_elf_rewrite_target_profile_reason_str(
    n00b_elf_rewrite_target_profile_reason_t reason);

/**
 * @param strategy Metadata table placement strategy.
 * @return Stable process-lifetime enum-name string.
 */
extern n00b_string_t *n00b_elf_rewrite_table_strategy_str(
    n00b_elf_rewrite_table_strategy_t strategy);

/**
 * @param kind Planned byte-range patch kind.
 * @return Stable process-lifetime enum-name string.
 */
extern n00b_string_t *n00b_elf_rewrite_patch_kind_str(
    n00b_elf_rewrite_patch_kind_t kind);

/**
 * @param status Relocated-PHTAB planning status.
 * @return Stable process-lifetime enum-name string.
 */
extern n00b_string_t *n00b_elf_rewrite_loadable_relocation_status_str(
    n00b_elf_rewrite_loadable_relocation_status_t status);
