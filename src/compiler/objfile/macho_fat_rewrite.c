/**
 * @file macho_fat_rewrite.c
 * @brief Fat / universal Mach-O rewrite — slice selection + per-slice thin
 *        rewrite (WP-007 Phase 1).
 *
 * Phase 1 implements `n00b_macho_fat_select` (per-slice disposition), the
 * per-slice thin-bytes producer (`_n00b_macho_fat_slice_thin_bytes`), and the
 * three `*_str` mappers.
 *
 * Phase 2 adds the re-fat primitive (`n00b_macho_refat`) and the orchestration
 * entrypoint (`n00b_macho_fat_rewrite`). The re-fat serialization itself lives
 * in `_n00b_macho_refat_serialize` (`macho_build.c`), the shared seam that
 * `n00b_macho_build_fat` also calls — so build_fat and refat agree on the
 * big-endian `fat_header`/`fat_arch[]` format and the checked `2^align`
 * placement (NFR-11). `n00b_macho_refat` parameterizes per-slice alignment;
 * `n00b_macho_build_fat` uses align == 14 for every slice.
 *
 * Per-slice rewrite discipline (D-034): a `REWRITE` slice's bytes are extracted
 * into a fresh detached buffer and re-parsed via `n00b_macho_parse_single`, so
 * the resulting binary has `fat_offset == 0` and the thin engine emits
 * slice-relative bytes. Mirrors the §3 thin rewrite invocation per slice. The
 * carrier (D-035) is applied to the arm64 `REWRITE` slice only; `PASSTHROUGH`
 * slices (every non-arm64 slice; D-002) are byte-identical.
 */

#include "compiler/objfile/macho_fat_rewrite.h"
#include "internal/compiler/objfile/macho_fat_rewrite_internal.h"

#include "compiler/objfile/macho_types.h"
#include "compiler/objfile/bstream.h"

// ============================================================================
// Internal helpers
// ============================================================================

// True when a slice CPU type is an arm64 rewrite target (D-002/D-035): x86_64
// (and every non-arm64) slice is never a rewrite target.
static inline bool
fat_cputype_is_rewrite_target(uint32_t cputype)
{
    return cputype == (uint32_t)CPU_TYPE_ARM64;
}

// Extract a slice's on-disk bytes from the fat input buffer into a fresh
// detached buffer (D-034). Reads the source extent through the parsed binary's
// own stream buffer (the whole fat file), copying [offset, offset + size).
static n00b_result_t(n00b_buffer_t *)
fat_extract_slice_bytes(n00b_macho_fat_t *fat,
                        uint32_t          index,
                        n00b_allocator_t *allocator)
{
    n00b_macho_binary_t    *bin   = fat->binaries[index];
    n00b_macho_fat_slice_t *slice = &fat->slices[index];

    if (bin == nullptr || bin->stream == nullptr
        || bin->stream->buf == nullptr) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_FAT_ERR_NULL_INPUT);
    }

    n00b_buffer_t *src = bin->stream->buf;
    uint64_t       off = slice->offset;
    uint64_t       sz  = slice->size;

    // The extent must lie within the source buffer.
    if (sz == 0 || off > (uint64_t)src->byte_len
        || sz > (uint64_t)src->byte_len - off) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_FAT_ERR_NOT_FAT);
    }

    n00b_buffer_t *out = n00b_buffer_from_bytes(src->data + off,
                                                (int64_t)sz,
                                                .allocator = allocator);

    return n00b_result_ok(n00b_buffer_t *, out);
}

// ============================================================================
// Per-slice thin-bytes producer (internal seam)
// ============================================================================

n00b_result_t(n00b_buffer_t *)
_n00b_macho_fat_slice_thin_bytes(
    n00b_macho_fat_t                      *fat,
    uint32_t                               index,
    n00b_macho_fat_slice_disposition_t     disposition,
    n00b_macho_rewrite_metadata_request_t *carrier,
    n00b_allocator_t                      *allocator)
    // No live `requires` (D-031): null fat/binaries/slices, `index >=
    // fat->count`, and a REJECT disposition are all documented `Err(...)`
    // returns guarded in the body; a trapping `requires` would SIGTRAP in debug
    // before the body could return the documented Err.
    ensures {
        // On Ok the returned thin buffer is non-null. Guarded by success
        // (D-028): on Err, result.ok is invalid.
        !result.is_ok || result.ok != nullptr;
    }
{
    // A nullptr allocator threads through to the runtime default; no explicit
    // resolution needed (the n00b_alloc family resolves it).
    if (fat == nullptr || fat->binaries == nullptr || fat->slices == nullptr
        || index >= fat->count) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_FAT_ERR_NULL_INPUT);
    }

    if (disposition == N00B_MACHO_FAT_SLICE_REJECT) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_FAT_ERR_NO_TARGET_SLICE);
    }

    // Both REWRITE and PASSTHROUGH start from the detached slice extent.
    n00b_buffer_t *slice_bytes = fat_extract_slice_bytes(fat,
                                                         index,
                                                         allocator)!;

    if (disposition == N00B_MACHO_FAT_SLICE_PASSTHROUGH) {
        // Byte-identical passthrough (D-002/D-035): no rewrite.
        return n00b_result_ok(n00b_buffer_t *, slice_bytes);
    }

    // REWRITE: parse the detached bytes as a thin object so fat_offset == 0
    // (D-034), then run the thin rewrite engine slice-relative.
    n00b_bstream_t *stream = n00b_bstream_new(slice_bytes,
                                              .allocator = allocator);

    n00b_result_t(n00b_macho_binary_t *) parsed
        = n00b_macho_parse_single(stream);

    if (n00b_result_is_err(parsed)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_FAT_ERR_SLICE_REWRITE);
    }

    n00b_macho_binary_t *thin = n00b_result_get(parsed);

    // D-034 invariant: the detached re-parse must be slice-relative.
    if (thin->fat_offset != 0) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_FAT_ERR_SLICE_REWRITE);
    }

    if (carrier == nullptr) {
        // No carrier request: the detached thin bytes are the output. They are
        // already a valid, re-parseable thin object (verified by P1-c).
        return n00b_result_ok(n00b_buffer_t *, slice_bytes);
    }

    // Apply the thin metadata carrier (WP-005 §3 engine) slice-relative.
    n00b_result_t(n00b_buffer_t *) applied
        = n00b_macho_rewrite_apply_metadata_insert(thin,
                                                   carrier,
                                                   .allocator = allocator);

    if (n00b_result_is_err(applied)) {
        return n00b_result_err(n00b_buffer_t *,
                               N00B_MACHO_FAT_ERR_SLICE_REWRITE);
    }

    return n00b_result_ok(n00b_buffer_t *, n00b_result_get(applied));
}

// ============================================================================
// Slice selection
// ============================================================================

n00b_result_t(n00b_list_t(n00b_macho_fat_rewrite_slice_plan_t *) *)
n00b_macho_fat_select(n00b_macho_fat_t                 *fat,
                      n00b_macho_fat_rewrite_request_t *req) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
    // ALL input validation is via documented `Err` returns, with NO trapping
    // `requires` (D-031): a null fat/binaries/slices/req AND `fat->count == 0`
    // are all documented `Err(N00B_MACHO_FAT_ERR_NULL_INPUT)` returns guarded in
    // the body, and a policy yielding no target is a documented
    // `Err(N00B_MACHO_FAT_ERR_NO_TARGET_SLICE)`. A live trapping `requires`
    // would SIGTRAP in debug before the body could return the documented Err.
    ensures {
        // On Ok the returned plan list is non-null. Guarded by success
        // (D-028): on Err, result.ok is invalid. The "exactly fat->count plans,
        // >= 1 REWRITE" postcondition is a list-length relation; ncc forbids
        // function calls in contracts (§0.3) and the list length is not plain
        // field access, so it is enforced while building the list and verified
        // by the P1 test matrix, expressed as Doxygen @post prose only.
        !result.is_ok || result.ok != nullptr;
    }
{
    if (fat == nullptr || fat->binaries == nullptr || fat->slices == nullptr
        || req == nullptr || fat->count == 0) {
        return n00b_result_err(n00b_list_t(
                                   n00b_macho_fat_rewrite_slice_plan_t *) *,
                               N00B_MACHO_FAT_ERR_NULL_INPUT);
    }

    // Decide which slice index is the (sole) rewrite target before building the
    // plan list. N00B_MACHO_LAYOUT_NO_INDEX-style sentinel: fat->count means
    // "no target chosen yet / not applicable".
    uint32_t target_index = fat->count; // sentinel: none
    bool     all_arm       = (req->policy == N00B_MACHO_FAT_SELECT_ALL_ARM);

    switch (req->policy) {
    case N00B_MACHO_FAT_SELECT_EXPLICIT_INDEX:
        if (req->explicit_index < fat->count
            && fat_cputype_is_rewrite_target(
                fat->slices[req->explicit_index].cputype)) {
            target_index = req->explicit_index;
        }
        break;
    case N00B_MACHO_FAT_SELECT_ALL_ARM:
        // Every arm64 slice is a target; handled per-slice below.
        break;
    case N00B_MACHO_FAT_SELECT_ARM64_ONLY:
    default:
        // First arm64 slice is the target.
        for (uint32_t i = 0; i < fat->count; i++) {
            if (fat_cputype_is_rewrite_target(fat->slices[i].cputype)) {
                target_index = i;
                break;
            }
        }
        break;
    }

    // Build the per-slice plan list and count rewrite targets.
    n00b_list_t(n00b_macho_fat_rewrite_slice_plan_t *) plans =
        n00b_list_new(n00b_macho_fat_rewrite_slice_plan_t *,
                      .allocator = allocator);
    n00b_list_t(n00b_macho_fat_rewrite_slice_plan_t *) *result =
        n00b_alloc(n00b_list_t(n00b_macho_fat_rewrite_slice_plan_t *),
                   .allocator = allocator);
    *result = plans;

    uint32_t rewrite_count = 0;

    for (uint32_t i = 0; i < fat->count; i++) {
        n00b_macho_fat_rewrite_slice_plan_t *plan =
            n00b_alloc(n00b_macho_fat_rewrite_slice_plan_t,
                       .allocator = allocator);

        plan->index   = i;
        plan->cputype = fat->slices[i].cputype;
        plan->align   = fat->slices[i].align;

        bool is_target = all_arm
                             ? fat_cputype_is_rewrite_target(
                                   fat->slices[i].cputype)
                             : (i == target_index);

        if (is_target) {
            plan->disposition = N00B_MACHO_FAT_SLICE_REWRITE;
            rewrite_count++;
        }
        else {
            // x86_64 and every non-target slice pass through (D-002/D-035).
            plan->disposition = N00B_MACHO_FAT_SLICE_PASSTHROUGH;
        }

        n00b_list_push(*result, plan);
    }

    if (rewrite_count == 0) {
        return n00b_result_err(n00b_list_t(
                                   n00b_macho_fat_rewrite_slice_plan_t *) *,
                               N00B_MACHO_FAT_ERR_NO_TARGET_SLICE);
    }

    return n00b_result_ok(
        n00b_list_t(n00b_macho_fat_rewrite_slice_plan_t *) *,
        result);
}

// ============================================================================
// Re-fat primitive (NFR-11 core)
// ============================================================================

n00b_result_t(n00b_buffer_t *)
n00b_macho_refat(n00b_buffer_t **thin_slices,
                 uint32_t       *cputypes,
                 uint32_t       *cpusubtypes,
                 uint32_t       *aligns,
                 uint32_t        count) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
    // No trapping `requires` (D-031): null arrays and `count == 0` are
    // documented `Err(N00B_MACHO_FAT_ERR_NULL_INPUT)` returns guarded in the
    // body. A live trapping `requires` would SIGTRAP in debug before the body
    // could return the documented Err.
    ensures {
        // On Ok the returned buffer is non-null (D-028: on Err result.ok is
        // invalid). "each fat_arch.offset == align_up(prev_end, 1u<<aligns[i])
        // and fits u32, strictly increasing" is enforced while building the
        // arch table in _n00b_macho_refat_serialize and verified by the P2
        // matrix; ncc has no old() (§7), so it is Doxygen @post prose only.
        !result.is_ok || result.ok != nullptr;
    }
{
    if (thin_slices == nullptr || cputypes == nullptr || cpusubtypes == nullptr
        || aligns == nullptr || count == 0) {
        return n00b_result_err(n00b_buffer_t *, N00B_MACHO_FAT_ERR_NULL_INPUT);
    }

    // The allocator backs the serializer's scratch arrays AND owns the
    // returned buffer: _n00b_macho_refat_serialize constructs the object writer
    // with this allocator, so the finalized fat buffer is owned by it directly,
    // with no re-home copy (DF-007-01 / NFR-04 / NFR-05).
    return _n00b_macho_refat_serialize(thin_slices,
                                       cputypes,
                                       cpusubtypes,
                                       aligns,
                                       count,
                                       allocator);
}

// ============================================================================
// Orchestration entrypoint
// ============================================================================

n00b_result_t(n00b_macho_fat_rewrite_result_t *)
n00b_macho_fat_rewrite(n00b_macho_fat_t                 *fat,
                       n00b_macho_fat_rewrite_request_t *req) _kargs {
    n00b_allocator_t *allocator = nullptr;
}
    // No trapping `requires` (D-031): null fat/binaries/req and `fat->count ==
    // 0` are documented `Err(N00B_MACHO_FAT_ERR_NULL_INPUT)` returns guarded in
    // the body. A live trapping `requires` would SIGTRAP in debug before the
    // body could return the documented Err.
    ensures {
        // On Ok every input slice is represented exactly once in the output
        // (D-028: on Err result.ok is invalid). The "every fat_arch.offset is
        // 2^align-aligned and strictly increasing" half is enforced in the
        // serializer and verified by the P2 matrix (§7: no old()).
        !result.is_ok || (result.ok->slice_count == fat->count);
    }
{
    if (fat == nullptr || fat->binaries == nullptr || fat->slices == nullptr
        || req == nullptr || fat->count == 0) {
        return n00b_result_err(n00b_macho_fat_rewrite_result_t *,
                               N00B_MACHO_FAT_ERR_NULL_INPUT);
    }

    // Classify every slice per the request policy (Phase 1).
    n00b_result_t(n00b_list_t(n00b_macho_fat_rewrite_slice_plan_t *) *) sel
        = n00b_macho_fat_select(fat, req, .allocator = allocator);

    if (n00b_result_is_err(sel)) {
        // Propagate the selector's verdict (NULL_INPUT / NO_TARGET_SLICE).
        return n00b_result_err(n00b_macho_fat_rewrite_result_t *,
                               n00b_result_get_err(sel));
    }

    n00b_list_t(n00b_macho_fat_rewrite_slice_plan_t *) *plans
        = n00b_result_get(sel);

    uint32_t count = fat->count;

    // Per-slice thin bytes + the identity the serializer needs.
    n00b_buffer_t **thin_bufs   = n00b_alloc_array(n00b_buffer_t *, count,
                                                   .allocator = allocator);
    uint32_t       *cputypes    = n00b_alloc_array(uint32_t, count,
                                                   .allocator = allocator);
    uint32_t       *cpusubtypes = n00b_alloc_array(uint32_t, count,
                                                   .allocator = allocator);
    uint32_t       *aligns      = n00b_alloc_array(uint32_t, count,
                                                   .allocator = allocator);

    n00b_macho_fat_rewrite_slice_range_t *ranges
        = n00b_alloc_array(n00b_macho_fat_rewrite_slice_range_t, count,
                           .allocator = allocator);

    for (uint32_t i = 0; i < count; i++) {
        n00b_macho_fat_rewrite_slice_plan_t *plan = n00b_list_get(*plans, i);

        // The carrier (D-035) is applied to the arm64 REWRITE slice only;
        // PASSTHROUGH slices get a null carrier (byte-identical, D-002/D-035).
        n00b_macho_rewrite_metadata_request_t *carrier
            = (plan->disposition == N00B_MACHO_FAT_SLICE_REWRITE)
                  ? req->carrier
                  : nullptr;

        n00b_result_t(n00b_buffer_t *) tr
            = _n00b_macho_fat_slice_thin_bytes(fat,
                                               plan->index,
                                               plan->disposition,
                                               carrier,
                                               allocator);

        if (n00b_result_is_err(tr)) {
            return n00b_result_err(n00b_macho_fat_rewrite_result_t *,
                                   n00b_result_get_err(tr));
        }

        thin_bufs[i]   = n00b_result_get(tr);
        // Per-slice cputype/align from the D-020 descriptor; cpusubtype from
        // the parsed binary header (not carried in the slice descriptor; D-020).
        cputypes[i]    = fat->slices[plan->index].cputype;
        cpusubtypes[i] = fat->binaries[plan->index]->header.cpusubtype;
        aligns[i]      = fat->slices[plan->index].align;

        ranges[i].index       = plan->index;
        ranges[i].cputype     = cputypes[i];
        ranges[i].align       = aligns[i];
        ranges[i].disposition = plan->disposition;
        // offset/size are filled below once the serializer fixes placement.
        ranges[i].offset = 0;
        ranges[i].size   = (uint64_t)n00b_buffer_len(thin_bufs[i]);
    }

    // Re-assemble the slices into a loader-valid fat container.
    n00b_result_t(n00b_buffer_t *) refat
        = n00b_macho_refat(thin_bufs,
                           cputypes,
                           cpusubtypes,
                           aligns,
                           count,
                           .allocator = allocator);

    if (n00b_result_is_err(refat)) {
        return n00b_result_err(n00b_macho_fat_rewrite_result_t *,
                               n00b_result_get_err(refat));
    }

    n00b_buffer_t *fat_buf = n00b_result_get(refat);

    // Re-parse the serialized container to recover each slice's authoritative
    // output offset (the serializer owns placement; mirror it into the ranges
    // rather than recompute the 2^align cursor here).
    n00b_bstream_t *rs = n00b_bstream_new(fat_buf, .allocator = allocator);
    n00b_result_t(n00b_macho_fat_t *) reparsed = n00b_macho_parse(rs);

    if (n00b_result_is_err(reparsed)) {
        return n00b_result_err(n00b_macho_fat_rewrite_result_t *,
                               N00B_MACHO_FAT_ERR_REFAT);
    }

    n00b_macho_fat_t *out_fat = n00b_result_get(reparsed);

    if (out_fat->count != count || out_fat->slices == nullptr) {
        return n00b_result_err(n00b_macho_fat_rewrite_result_t *,
                               N00B_MACHO_FAT_ERR_REFAT);
    }

    for (uint32_t i = 0; i < count; i++) {
        ranges[i].offset = out_fat->slices[i].offset;
        ranges[i].size   = out_fat->slices[i].size;
    }

    n00b_macho_fat_rewrite_result_t *result
        = n00b_alloc(n00b_macho_fat_rewrite_result_t, .allocator = allocator);

    result->buffer      = fat_buf;
    result->slices      = ranges;
    result->slice_count = count;

    return n00b_result_ok(n00b_macho_fat_rewrite_result_t *, result);
}

// ============================================================================
// Enum-name / error-string helpers (D-029: pointer-returning; NO ensures)
// ============================================================================

n00b_string_t *
n00b_macho_fat_slice_disposition_str(
    n00b_macho_fat_slice_disposition_t disposition)
{
    switch (disposition) {
    case N00B_MACHO_FAT_SLICE_REWRITE:
        return r"rewrite";
    case N00B_MACHO_FAT_SLICE_PASSTHROUGH:
        return r"passthrough";
    case N00B_MACHO_FAT_SLICE_REJECT:
        return r"reject";
    default:
        return r"unknown-macho-fat-slice-disposition";
    }
}

n00b_string_t *
n00b_macho_fat_select_policy_str(n00b_macho_fat_select_policy_t policy)
{
    switch (policy) {
    case N00B_MACHO_FAT_SELECT_ARM64_ONLY:
        return r"arm64-only";
    case N00B_MACHO_FAT_SELECT_ALL_ARM:
        return r"all-arm";
    case N00B_MACHO_FAT_SELECT_EXPLICIT_INDEX:
        return r"explicit-index";
    default:
        return r"unknown-macho-fat-select-policy";
    }
}

n00b_string_t *
n00b_macho_fat_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_MACHO_FAT_ERR_NULL_INPUT:
        return r"Mach-O fat: null input";
    case N00B_MACHO_FAT_ERR_NOT_FAT:
        return r"Mach-O fat: input is not a fat container";
    case N00B_MACHO_FAT_ERR_NO_TARGET_SLICE:
        return r"Mach-O fat: no rewrite-target slice selected";
    case N00B_MACHO_FAT_ERR_SLICE_REWRITE:
        return r"Mach-O fat: per-slice rewrite failed";
    case N00B_MACHO_FAT_ERR_ALIGN_OVERFLOW:
        return r"Mach-O fat: slice alignment cursor overflowed";
    case N00B_MACHO_FAT_ERR_SLICE_TOO_LARGE:
        return r"Mach-O fat: slice exceeds fat_arch 32-bit field";
    case N00B_MACHO_FAT_ERR_REFAT:
        return r"Mach-O fat: re-serialization failed";
    default:
        return r"Mach-O fat: unknown error code";
    }
}
