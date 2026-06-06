/**
 * @file elf_rewrite_admit.h
 * @brief Strict ELF rewrite admission vocabulary.
 *
 * The admission layer consumes an already parsed ELF object and a
 * metadata-section or loadable-segment insertion request. It is deliberately
 * separate from parsing: the parser stays lenient, and parse failures remain
 * `n00b_elf_parse()` errors rather than rewrite rejections.
 *
 * Admission is a read-only decision layer. It never mutates the parsed ELF
 * object, never emits replacement bytes, and never produces a patch plan.
 * Results are admission verdicts with placement or analysis facts. They are not
 * patch plans, and no returned offset authorizes mutation by itself.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/string.h"
#include "adt/option.h"
#include "adt/result.h"
#include "compiler/objfile/elf.h"

#define N00B_ELF_REWRITE_ADMIT_OK 0
#define N00B_ELF_REWRITE_ADMIT_ERR_NULL_BINARY       (-3501)
#define N00B_ELF_REWRITE_ADMIT_ERR_NULL_REQUEST      (-3502)
#define N00B_ELF_REWRITE_ADMIT_ERR_NULL_SECTION_NAME (-3503)
#define N00B_ELF_REWRITE_ADMIT_ERR_ZERO_PAYLOAD_SIZE (-3504)
#define N00B_ELF_REWRITE_ADMIT_ERR_LAYOUT_SUBSTRATE  (-3505)
#define N00B_ELF_REWRITE_ADMIT_ERR_OVERFLOW          (-3506)

typedef enum {
    N00B_ELF_REWRITE_ADMIT_POLICY_NONE = 0,
    N00B_ELF_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION = 1u << 0,
    /** Preserve existing overlay bytes; does not by itself choose placement. */
    N00B_ELF_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY           = 1u << 1,
    /** Permit EOF-tail placement after an overlay when preserve is also set. */
    N00B_ELF_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY       = 1u << 2,
} n00b_elf_rewrite_admit_policy_flag_t;

typedef struct n00b_elf_rewrite_admit_policy {
    uint64_t flags;
} n00b_elf_rewrite_admit_policy_t;

/**
 * @brief Metadata-section insertion request.
 *
 * The request borrows `section_name`; callers retain ownership and only need
 * it to remain alive for the admission call. The payload bytes themselves are
 * not supplied, only their size. `file_alignment == 0` is normalized to byte
 * alignment.
 *
 * Phase 2 admits only non-loadable metadata sections: `SHT_PROGBITS` or
 * `SHT_NOTE` with `section_flags == 0`.
 *
 * `preferred_file_offset` is an admission-only candidate. When set, admission
 * classifies exactly that file range and either returns a placement fact or a
 * stable rejection reason. It does not request byte mutation and is not a
 * patch-plan operation.
 */
typedef struct n00b_elf_rewrite_admit_metadata_request {
    n00b_string_t                     *section_name;
    uint64_t                           payload_size;
    uint64_t                           file_alignment;
    uint32_t                           section_type;
    uint64_t                           section_flags;
    n00b_option_t(uint64_t)            preferred_file_offset;
    n00b_elf_rewrite_admit_policy_t    policy;
} n00b_elf_rewrite_admit_metadata_request_t;

typedef enum {
    N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_NONE,
    N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_DEFERRED,
    N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_IN_PLACE_ADJUST,
    N00B_ELF_REWRITE_LOADABLE_PHTAB_STRATEGY_RELOCATE,
} n00b_elf_rewrite_loadable_phtab_strategy_t;

typedef enum {
    N00B_ELF_REWRITE_LOADABLE_PLACEMENT_NONE,
    N00B_ELF_REWRITE_LOADABLE_PLACEMENT_DEFERRED,
    N00B_ELF_REWRITE_LOADABLE_PLACEMENT_IN_PLACE_PHTAB,
    N00B_ELF_REWRITE_LOADABLE_PLACEMENT_RELOCATED_PHTAB,
    N00B_ELF_REWRITE_LOADABLE_PLACEMENT_LOADABLE_PAYLOAD,
} n00b_elf_rewrite_loadable_placement_kind_t;

typedef enum {
    N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_NONE,
    N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_ACCEPTED,
    N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_RELOCATABLE,
    N00B_ELF_REWRITE_LOADABLE_PHTAB_ADJUST_REJECTED_HARD,
} n00b_elf_rewrite_loadable_phtab_adjust_status_t;

/**
 * @brief Admission request for adding one ELF64 `PT_LOAD`.
 *
 * This metadata-only form carries the loadable segment's size and policy
 * facts without payload bytes. Byte-bearing planning uses the corresponding
 * rewrite-layer request.
 *
 * `file_alignment == 0` and `vaddr_alignment == 0` are normalized to byte
 * alignment. `p_memsz` must be at least `payload_size`; larger values model a
 * future zero-filled tail in memory.
 *
 * `phtab_strategy` selects whether admission only validates deferred facts,
 * runs in-place PHTAB adjustment analysis, or reserves relocated-PHTAB
 * planning for later rewrite phases. In-place analysis may produce concrete
 * PHTAB placement facts; payload placement and byte application remain
 * planner/apply responsibilities.
 */
typedef struct n00b_elf_rewrite_admit_loadable_request {
    uint64_t                                      payload_size;
    uint32_t                                      segment_flags;
    uint64_t                                      file_alignment;
    uint64_t                                      vaddr_alignment;
    uint64_t                                      p_memsz;
    n00b_elf_rewrite_loadable_phtab_strategy_t   phtab_strategy;
    n00b_elf_rewrite_admit_policy_t              policy;
} n00b_elf_rewrite_admit_loadable_request_t;

typedef enum {
    N00B_ELF_REWRITE_ADMIT_OUTCOME_ACCEPTED,
    N00B_ELF_REWRITE_ADMIT_OUTCOME_REJECTED,
} n00b_elf_rewrite_admit_outcome_t;

typedef enum {
    N00B_ELF_REWRITE_ADMIT_PLACEMENT_NONE,
    N00B_ELF_REWRITE_ADMIT_PLACEMENT_EOF_TAIL,
    N00B_ELF_REWRITE_ADMIT_PLACEMENT_FILE_GAP,
    N00B_ELF_REWRITE_ADMIT_PLACEMENT_AFTER_OVERLAY,
} n00b_elf_rewrite_admit_placement_kind_t;

typedef enum {
    N00B_ELF_REWRITE_ADMIT_REJECT_NONE,
    N00B_ELF_REWRITE_ADMIT_REJECT_NOT_YET_CHECKED,
    N00B_ELF_REWRITE_ADMIT_REJECT_RESERVED_SECTION_NAME,
    N00B_ELF_REWRITE_ADMIT_REJECT_SECTION_NOT_METADATA,
    N00B_ELF_REWRITE_ADMIT_REJECT_NO_SAFE_PLACEMENT,
    N00B_ELF_REWRITE_ADMIT_REJECT_FILE_COLLISION,
    N00B_ELF_REWRITE_ADMIT_REJECT_UNKNOWN_NONZERO_BYTES,
    N00B_ELF_REWRITE_ADMIT_REJECT_OVERLAY_POLICY,
    N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_OUTSIDE_LOAD,
    N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_MISSING,
    N00B_ELF_REWRITE_ADMIT_REJECT_PT_PHDR_INCONSISTENT,
    N00B_ELF_REWRITE_ADMIT_REJECT_ENTRY_OUTSIDE_LOAD,
    N00B_ELF_REWRITE_ADMIT_REJECT_ENTRY_MEMORY_ONLY,
    N00B_ELF_REWRITE_ADMIT_REJECT_LOADER_PRESERVATION,
    N00B_ELF_REWRITE_ADMIT_REJECT_INVALID_LOADABLE_REQUEST,
    N00B_ELF_REWRITE_ADMIT_REJECT_PAYLOAD_MEMSZ,
    N00B_ELF_REWRITE_ADMIT_REJECT_INVALID_PHTAB,
    N00B_ELF_REWRITE_ADMIT_REJECT_UNSUPPORTED_PN_XNUM,
    N00B_ELF_REWRITE_ADMIT_REJECT_RESERVED_TARGET,
    N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_MEMORY_COLLISION,
    N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_FILE_COLLISION,
    N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_NONZERO_SLACK,
    N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_AT_EOF,
    N00B_ELF_REWRITE_ADMIT_REJECT_PHTAB_ADJUST_EXTRA_DATA_BEFORE_EOF,
} n00b_elf_rewrite_admit_rejection_reason_t;

typedef struct n00b_elf_rewrite_admit_placement {
    n00b_elf_rewrite_admit_placement_kind_t kind;
    uint64_t                                file_offset;
    uint64_t                                file_end;
    uint64_t                                payload_size;
    uint64_t                                file_alignment;
} n00b_elf_rewrite_admit_placement_t;

typedef struct n00b_elf_rewrite_admit_result {
    n00b_elf_rewrite_admit_outcome_t             outcome;
    n00b_elf_rewrite_admit_rejection_reason_t    rejection_reason;
    n00b_option_t(n00b_elf_rewrite_admit_placement_t) placement;
    uint64_t                                     file_size;
    uint64_t                                     effective_alignment;
    n00b_elf_rewrite_admit_policy_t              policy;
} n00b_elf_rewrite_admit_result_t;

/**
 * @brief Planned loadable placement fact.
 *
 * Loadable admission can return concrete in-place PHTAB placement facts when
 * that analysis succeeds. The rewrite planner can later refine deferred
 * placement into relocated-PHTAB and payload ranges without changing the
 * admission verdict.
 */
typedef struct n00b_elf_rewrite_loadable_placement {
    n00b_elf_rewrite_loadable_placement_kind_t kind;
    uint64_t                                   file_offset;
    uint64_t                                   file_end;
    uint64_t                                   vaddr;
    uint64_t                                   vaddr_end;
    uint64_t                                   alignment;
} n00b_elf_rewrite_loadable_placement_t;

/**
 * @brief In-place PHTAB adjustment analysis facts.
 *
 * The analysis is read-only. Accepted facts describe how a later phase can
 * grow the existing PHTAB by one `Elf64_Phdr` while extending the containing
 * `PT_LOAD`. Rejected facts distinguish cases that later relocation planning
 * may try from hard malformed or unsupported target forms.
 */
typedef struct n00b_elf_rewrite_loadable_phtab_adjustment {
    n00b_elf_rewrite_loadable_phtab_adjust_status_t status;
    n00b_elf_rewrite_admit_rejection_reason_t       rejection_reason;
    uint32_t                                        containing_load_index;
    uint32_t                                        pt_phdr_index;
    bool                                            pt_phdr_present;
    uint64_t                                        original_phtab_offset;
    uint64_t                                        original_phtab_size;
    uint64_t                                        adjusted_phtab_offset;
    uint64_t                                        adjusted_phtab_size;
    uint64_t                                        adjusted_phtab_vaddr;
    uint64_t                                        required_file_extension;
    uint64_t                                        required_memory_extension;
    uint64_t                                        containing_load_file_end;
    uint64_t                                        containing_load_memory_end;
    uint64_t                                        zero_slack_start;
    uint64_t                                        zero_slack_end;
    uint64_t                                        next_file_object_offset;
    uint64_t                                        pt_phdr_new_offset;
    uint64_t                                        pt_phdr_new_filesz;
    uint64_t                                        pt_phdr_new_memsz;
    uint64_t                                        pt_phdr_new_vaddr;
} n00b_elf_rewrite_loadable_phtab_adjustment_t;

/**
 * @brief Admission result for adding one ELF64 `PT_LOAD`.
 *
 * Accepted results validate the request and target profile. They carry concrete
 * in-place PHTAB adjustment facts when that strategy succeeds, while payload
 * placement and byte-producing rewrite work remain deferred to later phases.
 */
typedef struct n00b_elf_rewrite_admit_loadable_result {
    n00b_elf_rewrite_admit_outcome_t             outcome;
    n00b_elf_rewrite_admit_rejection_reason_t    rejection_reason;
    n00b_elf_rewrite_loadable_phtab_strategy_t   phtab_strategy;
    n00b_elf_rewrite_loadable_placement_t        payload_placement;
    n00b_elf_rewrite_loadable_placement_t        phtab_placement;
    n00b_elf_rewrite_loadable_phtab_adjustment_t phtab_adjustment;
    uint64_t                                     file_size;
    uint64_t                                     original_segment_count;
    uint64_t                                     new_segment_count;
    uint64_t                                     payload_size;
    uint64_t                                     p_memsz;
    uint64_t                                     effective_file_alignment;
    uint64_t                                     effective_vaddr_alignment;
    uint32_t                                     segment_flags;
    n00b_elf_rewrite_admit_policy_t              policy;
    bool                                         entrypoint_policy_deferred;
} n00b_elf_rewrite_admit_loadable_result_t;

/**
 * @brief Admit a metadata-section insertion request.
 *
 * Valid metadata-only requests return an accepted verdict with concrete
 * placement facts. Unsafe rewrite cases return `Ok(rejected result)` with a
 * stable N00b-owned rejection reason; API and substrate failures return
 * `Err(N00B_ELF_REWRITE_ADMIT_ERR_*)`.
 *
 * This function does not perform byte mutation, table movement, patch
 * planning, loadable-segment insertion, or PHTAB adjustment planning.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @param request Metadata-section insertion request.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *               Used only for admission-owned layout substrate allocations.
 *
 * @return Ok(result) or Err(N00B_ELF_REWRITE_ADMIT_ERR_*).
 *
 * @pre `bin`, `request`, and `request->section_name` are non-null.
 * @pre `request->payload_size` is nonzero.
 * @post `bin` and its parsed sections, segments, stream, and overlay pointers
 *       are not modified.
 */
extern n00b_result_t(n00b_elf_rewrite_admit_result_t)
n00b_elf_rewrite_admit_metadata_insert(
    n00b_elf_binary_t                         *bin,
    n00b_elf_rewrite_admit_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Admit trusted Chalk-owned `.chalk.mark` metadata insertion.
 *
 * This is the reserved-name exception used by the lower-level rewrite layer
 * for Chalk. It accepts only an exact `.chalk.mark` request and only when the
 * target has no live reserved metadata section. All ordinary metadata,
 * placement, overlay, and loader-preservation checks still apply.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @param request Metadata-section insertion request.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *
 * @return Ok(result) or Err(N00B_ELF_REWRITE_ADMIT_ERR_*).
 *
 * @pre `bin`, `request`, and `request->section_name` are non-null.
 * @pre `request->payload_size` is nonzero.
 * @post `bin` and its parsed sections, segments, stream, and overlay pointers
 *       are not modified.
 */
extern n00b_result_t(n00b_elf_rewrite_admit_result_t)
n00b_elf_rewrite_admit_chalk_mark_insert(
    n00b_elf_binary_t                         *bin,
    n00b_elf_rewrite_admit_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Admit trusted N00b-owned `.0c001.bundle` metadata insertion.
 *
 * This is the reserved-name exception used by the lower-level rewrite layer
 * for object bundles. It accepts only an exact `.0c001.bundle` request, only
 * as non-loadable `SHT_PROGBITS` with `section_flags == 0`, and only when the
 * target has no live reserved N00b `.0c001.*` or guard section. Existing
 * `.chalk.mark` and `.chalk.free` sections are non-conflicting Chalk metadata
 * for this trusted path and are left to rewrite planning to preserve.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @param request Metadata-section insertion request.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *
 * @return Ok(result) or Err(N00B_ELF_REWRITE_ADMIT_ERR_*).
 *
 * @pre `bin`, `request`, and `request->section_name` are non-null.
 * @pre `request->payload_size` is nonzero.
 * @post `bin` and its parsed sections, segments, stream, and overlay pointers
 *       are not modified.
 */
extern n00b_result_t(n00b_elf_rewrite_admit_result_t)
n00b_elf_rewrite_admit_object_bundle_insert(
    n00b_elf_binary_t                         *bin,
    n00b_elf_rewrite_admit_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Admit a loadable-segment insertion request.
 *
 * Accepted results establish stable request and target facts for adding one
 * ELF64 `PT_LOAD`. In-place PHTAB adjustment can produce concrete PHTAB
 * placement facts; payload, relocated-PHTAB, and entrypoint patch bytes remain
 * deferred to rewrite planning/apply phases.
 *
 * Unsafe targets or malformed requests return `Ok(rejected result)` with a
 * stable rejection reason. API and substrate failures return
 * `Err(N00B_ELF_REWRITE_ADMIT_ERR_*)`.
 *
 * @param bin Parsed ELF object from @ref n00b_elf_parse.
 * @param request Loadable-segment admission request.
 * @kw allocator Defaults to `nullptr`, meaning the current runtime allocator.
 *               Used only for admission-owned layout substrate allocations.
 *
 * @return Ok(result) or Err(N00B_ELF_REWRITE_ADMIT_ERR_*).
 *
 * @pre `bin` and `request` are non-null.
 * @pre `request->payload_size` is nonzero.
 * @post `bin` and its parsed sections, segments, stream, and overlay pointers
 *       are not modified.
 */
extern n00b_result_t(n00b_elf_rewrite_admit_loadable_result_t)
n00b_elf_rewrite_admit_loadable_insert(
    n00b_elf_binary_t                         *bin,
    n00b_elf_rewrite_admit_loadable_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Look up a human-readable string for an admission error code.
 *
 * @param err Error code returned by the ELF rewrite admission API.
 *
 * @return A process-lifetime string literal. Unknown codes return a stable
 *         fallback message.
 */
extern n00b_string_t *
n00b_elf_rewrite_admit_err_str(n00b_err_t err);

/**
 * @brief Look up a stable name for a rewrite admission policy flag.
 *
 * @param flag One `N00B_ELF_REWRITE_ADMIT_POLICY_*` flag.
 *
 * @return A process-lifetime string literal. Unknown values return a stable
 *         fallback message.
 */
extern n00b_string_t *
n00b_elf_rewrite_admit_policy_flag_str(
    n00b_elf_rewrite_admit_policy_flag_t flag);

/**
 * @brief Look up a stable name for an admission outcome.
 *
 * @param outcome Admission outcome value.
 *
 * @return A process-lifetime string literal. Unknown values return a stable
 *         fallback message.
 */
extern n00b_string_t *
n00b_elf_rewrite_admit_outcome_str(
    n00b_elf_rewrite_admit_outcome_t outcome);

/**
 * @brief Look up a stable name for a candidate placement kind.
 *
 * @param kind Placement kind value.
 *
 * @return A process-lifetime string literal. Unknown values return a stable
 *         fallback message.
 */
extern n00b_string_t *
n00b_elf_rewrite_admit_placement_kind_str(
    n00b_elf_rewrite_admit_placement_kind_t kind);

/**
 * @brief Look up a stable name for an admission rejection reason.
 *
 * @param reason Rejection reason value.
 *
 * @return A process-lifetime string literal. Unknown values return a stable
 *         fallback message.
 */
extern n00b_string_t *
n00b_elf_rewrite_admit_rejection_reason_str(
    n00b_elf_rewrite_admit_rejection_reason_t reason);

/**
 * @brief Look up a stable name for a loadable PHTAB strategy.
 *
 * @param strategy PHTAB strategy value.
 *
 * @return A process-lifetime string literal. Unknown values return a stable
 *         fallback message.
 */
extern n00b_string_t *
n00b_elf_rewrite_loadable_phtab_strategy_str(
    n00b_elf_rewrite_loadable_phtab_strategy_t strategy);

/**
 * @brief Look up a stable name for a loadable placement kind.
 *
 * @param kind Loadable placement kind value.
 *
 * @return A process-lifetime string literal. Unknown values return a stable
 *         fallback message.
 */
extern n00b_string_t *
n00b_elf_rewrite_loadable_placement_kind_str(
    n00b_elf_rewrite_loadable_placement_kind_t kind);

/**
 * @brief Look up a stable name for in-place PHTAB adjustment status.
 *
 * @param status PHTAB adjustment status value.
 *
 * @return A process-lifetime string literal. Unknown values return a stable
 *         fallback message.
 */
extern n00b_string_t *
n00b_elf_rewrite_loadable_phtab_adjust_status_str(
    n00b_elf_rewrite_loadable_phtab_adjust_status_t status);
