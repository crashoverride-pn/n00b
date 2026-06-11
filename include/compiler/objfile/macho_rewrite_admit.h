/**
 * @file macho_rewrite_admit.h
 * @brief Strict Mach-O rewrite admission vocabulary.
 *
 * The admission layer consumes an already-parsed Mach-O object and a metadata
 * (LC_NOTE) or loadable (`LC_SEGMENT_64`) insertion request. It is deliberately
 * separate from parsing: the parser stays lenient, and parse failures remain
 * `n00b_macho_parse_single()` errors rather than rewrite rejections.
 *
 * Admission is a read-only decision layer. It never mutates the parsed object,
 * never emits replacement bytes, and never produces a patch plan. Results are
 * admission verdicts with placement or analysis facts; no returned offset
 * authorizes mutation by itself.
 *
 * Mach-O-specific admission concerns: metadata insert needs load-command header
 * slack (room to grow the LC region without colliding with the first segment's
 * file bytes); loadable insert needs LC header slack for the new segment
 * command, must keep `__LINKEDIT` last, and must reconcile with the trailing
 * code-signature region; the arm64 host-entrypoint target redirects
 * `LC_MAIN.entryoff` into the new segment payload (arm64 `MH_EXECUTE` only).
 *
 * Mirrors `elf_rewrite_admit.h` for the Mach-O arm64 backend.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/string.h"
#include "adt/option.h"
#include "adt/result.h"
#include "compiler/objfile/macho.h"

// ============================================================================
// Error codes
// ============================================================================

#define N00B_MACHO_REWRITE_ADMIT_OK 0
#define N00B_MACHO_REWRITE_ADMIT_ERR_NULL_BINARY      (-3901)
#define N00B_MACHO_REWRITE_ADMIT_ERR_NULL_REQUEST     (-3902)
#define N00B_MACHO_REWRITE_ADMIT_ERR_ZERO_PAYLOAD     (-3903)
#define N00B_MACHO_REWRITE_ADMIT_ERR_LAYOUT_SUBSTRATE (-3904)
#define N00B_MACHO_REWRITE_ADMIT_ERR_OVERFLOW         (-3905)

// ============================================================================
// Reserved LC_NOTE `data_owner` tokens (single source of truth)
// ============================================================================

/// The reserved N00b object-bundle `data_owner` token (D-010). The trusted
/// `n00b_macho_rewrite_admit_object_bundle_insert` path admits only this exact
/// owner; the general `_metadata_insert` path rejects it with
/// `REJECT_RESERVED_NOTE_NAME`. Defined once here and referenced — never
/// duplicated as a literal. (Chalk's reserved token is `CHALK_MACHO_NOTE_OWNER`,
/// defined in `include/internal/chalk/macho_core.h`.)
#define N00B_MACHO_BUNDLE_NOTE_OWNER "n00b.0c001"

// ============================================================================
// Policy, requests
// ============================================================================

typedef enum {
    N00B_MACHO_REWRITE_ADMIT_POLICY_NONE                       = 0,
    N00B_MACHO_REWRITE_ADMIT_POLICY_STRICT_LOADER_PRESERVATION = 1u << 0,
    N00B_MACHO_REWRITE_ADMIT_POLICY_PRESERVE_OVERLAY           = 1u << 1,
    N00B_MACHO_REWRITE_ADMIT_POLICY_APPEND_AFTER_OVERLAY       = 1u << 2,
    /** Permit rewrite even though a code signature is present (it is stripped
        and re-applied later by the signing-reconciliation layer, WP-011). */
    N00B_MACHO_REWRITE_ADMIT_POLICY_ALLOW_RESIGN               = 1u << 3,
} n00b_macho_rewrite_admit_policy_flag_t;

typedef struct n00b_macho_rewrite_admit_policy {
    uint64_t flags;
} n00b_macho_rewrite_admit_policy_t;

/** Metadata (LC_NOTE) insertion request. Borrows note_owner/note_name. */
typedef struct n00b_macho_rewrite_admit_metadata_request {
    n00b_string_t                    *note_owner;   // LC_NOTE data_owner (16B)
    n00b_string_t                    *note_name;    // logical name, diagnostics
    uint64_t                          payload_size;
    uint64_t                          file_alignment;       // 0 -> byte
    n00b_option_t(uint64_t)           preferred_file_offset;
    n00b_macho_rewrite_admit_policy_t policy;
} n00b_macho_rewrite_admit_metadata_request_t;

/** Loadable LC_SEGMENT_64 insertion request (metadata-only, no payload bytes). */
typedef struct n00b_macho_rewrite_admit_loadable_request {
    uint64_t                          payload_size;
    uint32_t                          initprot;     // VM_PROT_*
    uint32_t                          maxprot;
    uint64_t                          file_alignment;   // 0 -> byte
    uint64_t                          vaddr_alignment;  // 0 -> byte (arm64: 0x4000)
    uint64_t                          vmsize;           // >= payload_size
    n00b_macho_rewrite_admit_policy_t policy;
} n00b_macho_rewrite_admit_loadable_request_t;

// ============================================================================
// Verdict / placement / rejection vocabulary
// ============================================================================

typedef enum {
    N00B_MACHO_REWRITE_ADMIT_OUTCOME_ACCEPTED,
    N00B_MACHO_REWRITE_ADMIT_OUTCOME_REJECTED,
} n00b_macho_rewrite_admit_outcome_t;

typedef enum {
    N00B_MACHO_REWRITE_ADMIT_PLACEMENT_NONE,
    N00B_MACHO_REWRITE_ADMIT_PLACEMENT_EOF_TAIL,
    N00B_MACHO_REWRITE_ADMIT_PLACEMENT_FILE_GAP,
    N00B_MACHO_REWRITE_ADMIT_PLACEMENT_AFTER_OVERLAY,
    N00B_MACHO_REWRITE_ADMIT_PLACEMENT_BEFORE_CODESIG, // insert ahead of CS tail
} n00b_macho_rewrite_admit_placement_kind_t;

typedef enum {
    N00B_MACHO_REWRITE_ADMIT_REJECT_NONE,
    N00B_MACHO_REWRITE_ADMIT_REJECT_NOT_YET_CHECKED,
    N00B_MACHO_REWRITE_ADMIT_REJECT_RESERVED_NOTE_NAME,
    N00B_MACHO_REWRITE_ADMIT_REJECT_NO_SAFE_PLACEMENT,
    N00B_MACHO_REWRITE_ADMIT_REJECT_FILE_COLLISION,
    N00B_MACHO_REWRITE_ADMIT_REJECT_UNKNOWN_NONZERO_BYTES,
    N00B_MACHO_REWRITE_ADMIT_REJECT_OVERLAY_POLICY,
    // load-command region:
    N00B_MACHO_REWRITE_ADMIT_REJECT_LC_HEADER_SLACK,       // no room for new LC
    N00B_MACHO_REWRITE_ADMIT_REJECT_LC_REGION_INCONSISTENT,
    // __LINKEDIT / code signature interaction:
    N00B_MACHO_REWRITE_ADMIT_REJECT_LINKEDIT_NOT_LAST,
    N00B_MACHO_REWRITE_ADMIT_REJECT_CODESIG_NOT_LAST,
    N00B_MACHO_REWRITE_ADMIT_REJECT_CODESIG_PRESENT_NO_RESIGN, // CS but no ALLOW_RESIGN
    // segment / vm:
    N00B_MACHO_REWRITE_ADMIT_REJECT_INVALID_LOADABLE_REQUEST,
    N00B_MACHO_REWRITE_ADMIT_REJECT_VMSIZE_TOO_SMALL,
    N00B_MACHO_REWRITE_ADMIT_REJECT_VADDR_COLLISION,
    N00B_MACHO_REWRITE_ADMIT_REJECT_FILEOFF_NOT_PAGE_ALIGNED,
    // entrypoint:
    N00B_MACHO_REWRITE_ADMIT_REJECT_ENTRY_OUTSIDE_SEGMENT,
    N00B_MACHO_REWRITE_ADMIT_REJECT_ENTRY_NOT_EXECUTABLE,
    N00B_MACHO_REWRITE_ADMIT_REJECT_UNSUPPORTED_CPUTYPE,   // not arm64
    N00B_MACHO_REWRITE_ADMIT_REJECT_NO_LC_MAIN,            // LC_UNIXTHREAD only
    N00B_MACHO_REWRITE_ADMIT_REJECT_RESERVED_TARGET,
    N00B_MACHO_REWRITE_ADMIT_REJECT_LOADER_PRESERVATION,
} n00b_macho_rewrite_admit_rejection_reason_t;

typedef struct n00b_macho_rewrite_admit_placement {
    n00b_macho_rewrite_admit_placement_kind_t kind;
    uint64_t file_offset;
    uint64_t file_end;
    uint64_t payload_size;
    uint64_t file_alignment;
} n00b_macho_rewrite_admit_placement_t;

typedef struct n00b_macho_rewrite_admit_result {
    n00b_macho_rewrite_admit_outcome_t          outcome;
    n00b_macho_rewrite_admit_rejection_reason_t rejection_reason;
    n00b_option_t(n00b_macho_rewrite_admit_placement_t) placement;
    uint64_t                                    file_size;
    uint64_t                                    effective_alignment;
    // load-command slack facts:
    uint64_t                                    lc_region_offset;
    uint64_t                                    lc_region_used;     // sizeofcmds
    uint64_t                                    lc_region_capacity; // to 1st seg
    uint64_t                                    lc_slack_bytes;
    bool                                        code_signature_present;
    uint64_t                                    code_signature_offset;
    uint64_t                                    code_signature_size;
    n00b_macho_rewrite_admit_policy_t           policy;
} n00b_macho_rewrite_admit_result_t;

/** Loadable admission result: one new LC_SEGMENT_64. */
typedef struct n00b_macho_rewrite_admit_loadable_result {
    n00b_macho_rewrite_admit_outcome_t          outcome;
    n00b_macho_rewrite_admit_rejection_reason_t rejection_reason;
    // new segment placement facts (file + vm):
    uint64_t                                    new_segment_file_offset;
    uint64_t                                    new_segment_file_end;
    uint64_t                                    new_segment_vaddr;
    uint64_t                                    new_segment_vaddr_end;
    uint64_t                                    payload_size;
    uint64_t                                    vmsize;
    uint64_t                                    effective_file_alignment;
    uint64_t                                    effective_vaddr_alignment;
    uint32_t                                    initprot;
    uint32_t                                    maxprot;
    // LC region growth + linkedit/codesig relocation facts:
    uint64_t                                    lc_slack_bytes;
    uint64_t                                    required_lc_growth; // 1 seg cmd
    bool                                        linkedit_must_move;
    uint64_t                                    linkedit_old_offset;
    uint64_t                                    linkedit_new_offset;
    bool                                        code_signature_present;
    uint64_t                                    code_signature_old_offset;
    uint64_t                                    original_segment_count;
    uint64_t                                    new_segment_count;
    uint64_t                                    file_size;
    n00b_macho_rewrite_admit_policy_t           policy;
    bool                                        entrypoint_policy_deferred;
} n00b_macho_rewrite_admit_loadable_result_t;

// ============================================================================
// Metadata-insert admission
// ============================================================================

/**
 * @brief Admit an LC_NOTE metadata-insertion request.
 *
 * Valid metadata-only requests return an accepted verdict with concrete
 * placement and load-command-slack facts. Unsafe cases return
 * `Ok(rejected result)` with a stable reason; API/substrate failures return
 * `Err(N00B_MACHO_REWRITE_ADMIT_ERR_*)`. Never mutates @p bin, never emits
 * bytes, never plans.
 *
 * @param bin Parsed Mach-O object from @ref n00b_macho_parse_single.
 * @param request LC_NOTE insertion request.
 * @kw allocator Defaults to `nullptr`; admission-owned layout substrate only.
 * @return Ok(result) or Err(N00B_MACHO_REWRITE_ADMIT_ERR_*).
 * @pre `bin`, `request`, and `request->note_owner` are non-null.
 * @pre `request->payload_size` is nonzero.
 * @post `bin` and its parsed segments, sections, stream, and overlay are
 *       not modified.   (no-`old` limit: byte non-mutation is test-verified.)
 * @post On accept, `result.ok.outcome == ACCEPTED` and a placement is set.
 * @post On reject, `result.ok.outcome == REJECTED` and `rejection_reason` is
 *       not `NONE`.
 */
extern n00b_result_t(n00b_macho_rewrite_admit_result_t)
n00b_macho_rewrite_admit_metadata_insert(
    n00b_macho_binary_t                         *bin,
    n00b_macho_rewrite_admit_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Admit a trusted Chalk LC_NOTE metadata-insertion request.
 *
 * Identical pre/post to @ref n00b_macho_rewrite_admit_metadata_insert, but
 * accepts only the exact reserved Chalk `data_owner`
 * (`CHALK_MACHO_NOTE_OWNER`, i.e. `"chalk"`; see
 * include/internal/chalk/macho_core.h). A non-matching `note_owner` is
 * rejected with `RESERVED_NOTE_NAME`.
 *
 * @param bin Parsed Mach-O object.
 * @param request LC_NOTE insertion request.
 * @kw allocator Defaults to `nullptr`; admission-owned substrate only.
 * @return Ok(result) or Err(N00B_MACHO_REWRITE_ADMIT_ERR_*).
 * @pre `bin`, `request`, and `request->note_owner` are non-null.
 * @pre `request->payload_size` is nonzero.
 * @post On a non-matching `note_owner`, `result.ok.outcome == REJECTED` with
 *       `rejection_reason == RESERVED_NOTE_NAME`.
 * @post Well-formed verdict: accept => placement set; reject => reason != NONE.
 */
extern n00b_result_t(n00b_macho_rewrite_admit_result_t)
n00b_macho_rewrite_admit_chalk_mark_insert(
    n00b_macho_binary_t                         *bin,
    n00b_macho_rewrite_admit_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Admit a trusted N00b object-bundle LC_NOTE metadata-insertion request.
 *
 * Identical pre/post to @ref n00b_macho_rewrite_admit_metadata_insert, but
 * accepts only the exact bundle `data_owner` (`N00B_MACHO_BUNDLE_NOTE_OWNER`,
 * i.e. `"n00b.0c001"`; D-010). A non-matching `note_owner` is rejected with
 * `RESERVED_NOTE_NAME`.
 *
 * @param bin Parsed Mach-O object.
 * @param request LC_NOTE insertion request.
 * @kw allocator Defaults to `nullptr`; admission-owned substrate only.
 * @return Ok(result) or Err(N00B_MACHO_REWRITE_ADMIT_ERR_*).
 * @pre `bin`, `request`, and `request->note_owner` are non-null.
 * @pre `request->payload_size` is nonzero.
 * @post On a non-matching `note_owner`, `result.ok.outcome == REJECTED` with
 *       `rejection_reason == RESERVED_NOTE_NAME`.
 * @post Well-formed verdict: accept => placement set; reject => reason != NONE.
 */
extern n00b_result_t(n00b_macho_rewrite_admit_result_t)
n00b_macho_rewrite_admit_object_bundle_insert(
    n00b_macho_binary_t                         *bin,
    n00b_macho_rewrite_admit_metadata_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Loadable-insert admission
// ============================================================================

/**
 * @brief Admit a single LC_SEGMENT_64 loadable-insert request.
 *
 * Accepted results establish stable request/target facts: new-segment file and
 * vm placement, load-command growth, whether __LINKEDIT (and any trailing code
 * signature) must move, and segment counts. Payload bytes, LC patching, and
 * entrypoint patch bytes are deferred to the rewrite layer.
 *
 * Load-command-slack exhaustion is an accepted-but-costly case, not a rejection
 * (D-021): if the available LC header slack (`lc_slack_bytes`) is less than the
 * new `LC_SEGMENT_64` cmdsize (`required_lc_growth`), the resulting plan path is
 * `__TEXT` section reflow (sliding `__TEXT` sections to open load-command room
 * and growing `__TEXT`), not merely `__LINKEDIT` relocation. The WP-001 spike
 * showed 32 B of slack against a 72 B segment command forced this reflow; the
 * loadable plan (`macho_rewrite.h`, §3.3) carries the concrete reflow facts.
 *
 * @param bin Parsed Mach-O object.
 * @param request Loadable-segment admission request.
 * @kw allocator Defaults to `nullptr`; admission-owned substrate only.
 * @return Ok(result) or Err(N00B_MACHO_REWRITE_ADMIT_ERR_*).
 * @pre `bin` and `request` are non-null.
 * @pre `request->payload_size` is nonzero.
 * @pre `request->vmsize >= request->payload_size`.
 * @post `bin` and its parsed arrays/stream/overlay are not modified.
 *       (no-`old` limit: byte non-mutation test-verified.)
 * @post On accept, the new segment vm extent is well-ordered and at least
 *       `payload_size` wide in file:
 *       `new_segment_file_end - new_segment_file_offset >= payload_size`.
 * @post On accept, `new_segment_count == original_segment_count + 1`.
 * @post On accept, `linkedit_new_offset` is 0: admission records only that
 *       `__LINKEDIT` must move (`linkedit_must_move`) and from where
 *       (`linkedit_old_offset`); the concrete relocated offset is computed by
 *       the rewrite layer (WP-006, `macho_rewrite.h`), not here. Consumers must
 *       not read `linkedit_new_offset` from an admission result as authoritative.
 * @post On accept when `lc_slack_bytes < required_lc_growth`, the accepted plan
 *       path is `__TEXT` section reflow rather than `__LINKEDIT`-only relocation
 *       (D-021); the reflow facts are carried on the loadable plan, not here.
 * @post On accept with a present code signature and without ALLOW_RESIGN
 *       policy, the result is instead REJECTED with CODESIG_PRESENT_NO_RESIGN.
 */
extern n00b_result_t(n00b_macho_rewrite_admit_loadable_result_t)
n00b_macho_rewrite_admit_loadable_insert(
    n00b_macho_binary_t                         *bin,
    n00b_macho_rewrite_admit_loadable_request_t *request) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// arm64 host-entrypoint admission
// ============================================================================

typedef struct n00b_macho_rewrite_admit_entrypoint_request {
    uint64_t target_segment_file_offset; // candidate new segment file base
    uint64_t target_segment_vaddr;       // candidate new segment vm base
    uint64_t target_payload_offset;      // offset within the segment payload
    uint64_t target_size;                // bytes of the target range
} n00b_macho_rewrite_admit_entrypoint_request_t;

typedef struct n00b_macho_rewrite_admit_entrypoint_result {
    n00b_macho_rewrite_admit_outcome_t          outcome;
    n00b_macho_rewrite_admit_rejection_reason_t rejection_reason;
    uint64_t                                    original_entryoff;   // LC_MAIN
    uint64_t                                    replacement_entryoff;// file off
    uint64_t                                    text_vmaddr;         // __TEXT base
    bool                                        has_lc_main;
    uint32_t                                    cputype;
} n00b_macho_rewrite_admit_entrypoint_result_t;

/**
 * @brief Admit arm64 LC_MAIN entrypoint redirection into a candidate segment.
 *
 * `LC_MAIN.entryoff` is a file offset relative to the start of the Mach-O
 * (the __TEXT vmaddr maps to file offset 0). Accepted results derive the
 * replacement `entryoff` from the candidate segment placement. Non-arm64,
 * non-MH_EXECUTE, LC_UNIXTHREAD-only, or out-of-range targets are rejected.
 * This API is accept-capable (D-009 confirmed FEASIBLE, D-021); there is no
 * `ERR_UNSUPPORTED` demotion.
 *
 * @param bin Parsed arm64 Mach-O executable.
 * @param request Candidate entrypoint target facts.
 * @return Ok(result) or Err(N00B_MACHO_REWRITE_ADMIT_ERR_*).
 * @pre `bin` and `request` are non-null.
 * @pre `request->target_size` is nonzero.
 * @post `bin` is not modified.
 * @post On accept, `result.ok.has_lc_main` and
 *       `result.ok.cputype == CPU_TYPE_ARM64`.
 */
extern n00b_result_t(n00b_macho_rewrite_admit_entrypoint_result_t)
n00b_macho_rewrite_admit_host_entrypoint_target(
    n00b_macho_binary_t                           *bin,
    n00b_macho_rewrite_admit_entrypoint_request_t *request);

// ============================================================================
// Enum-name / error-string helpers
// ============================================================================

/**
 * @brief Look up a human-readable string for an `N00B_MACHO_REWRITE_ADMIT_ERR_*`
 *        code.
 *
 * @param err Error code returned by the Mach-O admission API.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_rewrite_admit_err_str(n00b_err_t err);

/**
 * @brief Look up a stable name for a single Mach-O admission policy flag bit.
 *
 * @param flag One `N00B_MACHO_REWRITE_ADMIT_POLICY_*` flag.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_rewrite_admit_policy_flag_str(
    n00b_macho_rewrite_admit_policy_flag_t flag);

/**
 * @brief Look up a stable name for a Mach-O admission outcome.
 *
 * @param outcome Outcome value.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_rewrite_admit_outcome_str(
    n00b_macho_rewrite_admit_outcome_t outcome);

/**
 * @brief Look up a stable name for a Mach-O admission placement kind.
 *
 * @param kind Placement kind value.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_rewrite_admit_placement_kind_str(
    n00b_macho_rewrite_admit_placement_kind_t kind);

/**
 * @brief Look up a stable name for a Mach-O admission rejection reason.
 *
 * @param reason Rejection-reason value.
 * @return A process-lifetime string literal; unknown values return a stable
 *         fallback.
 */
extern n00b_string_t *
n00b_macho_rewrite_admit_rejection_reason_str(
    n00b_macho_rewrite_admit_rejection_reason_t reason);
