/**
 * @file macho_fat_rewrite.h
 * @brief Fat / universal Mach-O rewrite — slice selection, per-slice thin
 *        rewrite, and container re-assembly (re-fat).
 *
 * This layer sits ABOVE the single-slice rewrite engine (`macho_rewrite.h`,
 * §3 of 03-api-and-contracts). The thin engine scopes itself to one slice and
 * rejects fat input outright (`N00B_MACHO_REWRITE_PROFILE_FAT_UNSUPPORTED`).
 * Fat/universal handling is layered here (design 04 §6, 06-roadmap): parse the
 * fat container, classify each slice, run the thin rewrite on each chosen
 * arm64 slice, then re-assemble the slices into a loader-valid universal
 * container with correct per-slice page alignment.
 *
 * Per-slice rewrite discipline (D-034): each `REWRITE` slice is fed to the
 * thin engine as a DETACHED thin object — its bytes are extracted into a fresh
 * buffer and re-parsed via @ref n00b_macho_parse_single so `bin->fat_offset`
 * is zero and the thin engine emits slice-relative bytes that re-fat
 * repositions. A slice is never rewritten in place at its fat offset.
 *
 * Slice policy (D-035 / D-002): the bundle carrier applies to the arm64 slice
 * only; x86_64 (and every other non-arm64) slice is parsed and passed through
 * byte-identical, never rewritten.
 *
 * Symbol prefix: `n00b_macho_fat_*`. Error block `-43xx`.
 */
#pragma once

#include <stdint.h>

#include "n00b.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_rewrite.h"

// ============================================================================
// Error codes (block -43xx; D-022/D-036: admit -39xx, carrier -41xx,
// layout -42xx, fat -43xx, rewrite -44xx).
// ============================================================================

#define N00B_MACHO_FAT_OK                  0
#define N00B_MACHO_FAT_ERR_NULL_INPUT      (-4301) // null fat/binaries/req
#define N00B_MACHO_FAT_ERR_NOT_FAT         (-4302) // input thin; use thin path
#define N00B_MACHO_FAT_ERR_NO_TARGET_SLICE (-4303) // no arm64 rewrite target
#define N00B_MACHO_FAT_ERR_SLICE_REWRITE   (-4304) // a per-slice §3 rewrite failed
#define N00B_MACHO_FAT_ERR_ALIGN_OVERFLOW  (-4305) // 2^align cursor overflowed u64
#define N00B_MACHO_FAT_ERR_SLICE_TOO_LARGE (-4306) // slice exceeds fat_arch u32 field
#define N00B_MACHO_FAT_ERR_REFAT           (-4307) // re-serialization failed

// ============================================================================
// Enums
// ============================================================================

/** Per-slice disposition chosen by @ref n00b_macho_fat_select. */
typedef enum {
    N00B_MACHO_FAT_SLICE_REWRITE,     ///< Run the thin carrier/rewrite on this slice.
    N00B_MACHO_FAT_SLICE_PASSTHROUGH, ///< Copy this slice through byte-identical.
    N00B_MACHO_FAT_SLICE_REJECT,      ///< Slice rejected by policy (no output).
} n00b_macho_fat_slice_disposition_t;

/** Slice-selection policy. `ARM64_ONLY` is the default (04 §6 (a) / D-035). */
typedef enum {
    N00B_MACHO_FAT_SELECT_ARM64_ONLY = 0, ///< Rewrite the arm64 slice; others passthrough.
    N00B_MACHO_FAT_SELECT_ALL_ARM,        ///< Rewrite every arm64 slice; others passthrough.
    N00B_MACHO_FAT_SELECT_EXPLICIT_INDEX, ///< Rewrite exactly the requested slice index.
} n00b_macho_fat_select_policy_t;

// ============================================================================
// Request / plan / result types
// ============================================================================

/**
 * @brief Fat-rewrite request: selector policy + per-slice carrier request.
 *
 * `policy` chooses which slice(s) are rewrite targets. `explicit_index` is
 * consumed only when `policy == N00B_MACHO_FAT_SELECT_EXPLICIT_INDEX`; an
 * index `>= fat->count` selects no target (NO_TARGET_SLICE). `carrier` is the
 * thin metadata-carrier request applied to each `REWRITE` slice; it is borrowed
 * (not copied) and may be `nullptr` when no carrier is requested (the slice is
 * still re-emitted as detached thin bytes per D-034).
 */
typedef struct n00b_macho_fat_rewrite_request {
    n00b_macho_fat_select_policy_t         policy;
    uint32_t                               explicit_index;
    n00b_macho_rewrite_metadata_request_t *carrier;
} n00b_macho_fat_rewrite_request_t;

/**
 * @brief One slice's selection outcome.
 *
 * Parallel to `fat->binaries[index]` / `fat->slices[index]`. `disposition`
 * records whether the slice is a rewrite target, a byte-identical passthrough,
 * or rejected. `cputype`/`align` mirror the D-020 slice descriptor for the
 * convenience of re-fat consumers.
 */
typedef struct n00b_macho_fat_rewrite_slice_plan {
    uint32_t                           index;       ///< Slice index in fat->binaries/slices.
    uint32_t                           cputype;     ///< Slice CPU type (D-020).
    uint32_t                           align;       ///< Slice 2^align exponent (D-020).
    n00b_macho_fat_slice_disposition_t disposition; ///< Chosen disposition.
} n00b_macho_fat_rewrite_slice_plan_t;

/**
 * @brief One re-fattened slice's placement in the output container.
 *
 * Records where each slice landed in the re-fattened buffer and which
 * disposition produced its bytes.
 */
typedef struct n00b_macho_fat_rewrite_slice_range {
    uint32_t                           index;       ///< Slice index.
    uint32_t                           cputype;     ///< Slice CPU type.
    uint32_t                           align;       ///< Slice 2^align exponent.
    n00b_macho_fat_slice_disposition_t disposition; ///< How the bytes were produced.
    uint64_t                           offset;      ///< Output file offset of the slice.
    uint64_t                           size;        ///< Output slice byte size.
} n00b_macho_fat_rewrite_slice_range_t;

/**
 * @brief Result of @ref n00b_macho_fat_rewrite: the re-fattened container.
 *
 * `buffer` is the loader-valid universal container. `slices`/`slice_count`
 * record each slice's output placement (offset/size/alignment/disposition).
 * `slice_count` equals the input `fat->count`.
 */
typedef struct n00b_macho_fat_rewrite_result {
    n00b_buffer_t                        *buffer;      ///< Re-fattened bytes.
    n00b_macho_fat_rewrite_slice_range_t *slices;      ///< Per-slice placement facts.
    uint32_t                              slice_count; ///< Number of output slices.
} n00b_macho_fat_rewrite_result_t;

// ============================================================================
// Slice selection
// ============================================================================

/**
 * @brief Classify each slice of a parsed fat container per the request policy.
 *
 * Walks `fat->binaries[0..count)` and, reading each slice's CPU type from the
 * D-020 descriptor `fat->slices[i].cputype`, assigns a disposition:
 * - `ARM64_ONLY`: the first arm64 slice → `REWRITE`; all others → `PASSTHROUGH`.
 * - `ALL_ARM`: every arm64 slice → `REWRITE`; all others → `PASSTHROUGH`.
 * - `EXPLICIT_INDEX`: the requested index → `REWRITE` (only if it is arm64);
 *   all others → `PASSTHROUGH`.
 *
 * x86_64 (and every non-arm64) slice is always `PASSTHROUGH` (D-002). If the
 * policy yields no `REWRITE` target (e.g. an out-of-range explicit index, or no
 * arm64 slice present), the call returns `Err(N00B_MACHO_FAT_ERR_NO_TARGET_SLICE)`.
 *
 * @param fat Parsed fat container from @ref n00b_macho_parse (count >= 1).
 * @param req Selection request (policy + explicit index + carrier).
 * @kw allocator Defaults to `nullptr`; owns the returned plan list.
 * @return Ok(list of per-slice plans, one per input slice in index order), or
 *         Err(N00B_MACHO_FAT_ERR_*) (NULL_INPUT, NO_TARGET_SLICE).
 * @pre `fat`, `fat->binaries`, `fat->slices`, and `req` are non-null. (Advisory;
 *      D-031: a null input is a documented `Err(N00B_MACHO_FAT_ERR_NULL_INPUT)`
 *      return guarded in the body, not a trapping precondition.)
 * @pre `fat->count` is nonzero.
 * @post On Ok, the list has exactly `fat->count` plans, each with a valid
 *       disposition, and at least one plan is `REWRITE`.
 */
extern n00b_result_t(n00b_list_t(n00b_macho_fat_rewrite_slice_plan_t *) *)
n00b_macho_fat_select(n00b_macho_fat_t                 *fat,
                      n00b_macho_fat_rewrite_request_t *req) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Orchestration entrypoint + re-fat primitive (Phase 2 — declared here per the
// §8 surface; defined in Phase 2).
// ============================================================================

/**
 * @brief Rewrite a fat/universal container per the request and re-assemble it.
 *
 * Selects per `req->policy`, runs the thin §3 rewrite on each `REWRITE` slice
 * as a detached thin object (D-034), passes other slices through byte-identical
 * (D-035/D-002), then re-fats the slices into a loader-valid universal
 * container with correct `2^align` offsets.
 *
 * @param fat Parsed fat container from @ref n00b_macho_parse.
 * @param req Fat-rewrite request.
 * @kw allocator Defaults to `nullptr` (runtime allocator). Owns the returned
 *     result struct, its per-slice range array, AND the result's `buffer`
 *     field (and backs intermediate allocations).
 * @return Ok(result) or Err(N00B_MACHO_FAT_ERR_*).
 * @pre `fat`, `fat->binaries`, and `req` are non-null; `fat->count` is nonzero.
 * @post On Ok, `result->slice_count == fat->count` and every output
 *       `fat_arch.offset` is `2^align`-aligned and strictly increasing.
 */
extern n00b_result_t(n00b_macho_fat_rewrite_result_t *)
n00b_macho_fat_rewrite(n00b_macho_fat_t                 *fat,
                       n00b_macho_fat_rewrite_request_t *req) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Re-assemble thin slices into a loader-valid fat/universal container.
 *
 * Writes a big-endian `fat_header` + `fat_arch[]` table (`FAT_MAGIC`), placing
 * each slice at the running `2^aligns[i]`-aligned cursor. Overflow of the
 * running cursor or a slice whose offset/size exceeds the `fat_arch` u32 field
 * is reported as an error, never silently truncated.
 *
 * @param thin_slices Array of `count` thin slice buffers, in output order.
 * @param cputypes Per-slice CPU types (`count` entries).
 * @param cpusubtypes Per-slice CPU subtypes (`count` entries).
 * @param aligns Per-slice 2^align exponents (`count` entries).
 * @param count Number of slices; nonzero.
 * @kw allocator Defaults to `nullptr` (runtime allocator). Backs the
 *     serializer's scratch / intermediate allocations and OWNS the returned
 *     buffer.
 * @return Ok(buffer) or Err(N00B_MACHO_FAT_ERR_*) (ALIGN_OVERFLOW,
 *         SLICE_TOO_LARGE, REFAT).
 * @pre `thin_slices`, `cputypes`, `cpusubtypes`, `aligns` are non-null and
 *      `count` is nonzero.
 * @post On Ok, each `fat_arch.offset == align_up(prev_end, 1u << aligns[i])`
 *       and fits the u32 `fat_arch` field; offsets are strictly increasing.
 */
extern n00b_result_t(n00b_buffer_t *)
n00b_macho_refat(n00b_buffer_t **thin_slices,
                 uint32_t       *cputypes,
                 uint32_t       *cpusubtypes,
                 uint32_t       *aligns,
                 uint32_t        count) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

// ============================================================================
// Enum-name / error-string helpers (D-029: pointer-returning; NO ensures).
// ============================================================================

/**
 * @brief Look up a stable name for a fat-slice disposition.
 *
 * @param disposition Disposition value.
 * @return A process-lifetime string literal (never null); defined values
 *         return a non-fallback name, unknown values a stable fallback.
 */
extern n00b_string_t *
n00b_macho_fat_slice_disposition_str(
    n00b_macho_fat_slice_disposition_t disposition);

/**
 * @brief Look up a stable name for a fat-slice-selection policy.
 *
 * @param policy Policy value.
 * @return A process-lifetime string literal (never null); defined values
 *         return a non-fallback name, unknown values a stable fallback.
 */
extern n00b_string_t *
n00b_macho_fat_select_policy_str(n00b_macho_fat_select_policy_t policy);

/**
 * @brief Look up a human-readable string for an `N00B_MACHO_FAT_ERR_*` code.
 *
 * @param err Error code returned by the fat-rewrite API.
 * @return A process-lifetime string literal (never null); defined `-43xx`
 *         codes return a non-fallback message, unknown values a stable fallback.
 */
extern n00b_string_t *
n00b_macho_fat_err_str(n00b_err_t err);
