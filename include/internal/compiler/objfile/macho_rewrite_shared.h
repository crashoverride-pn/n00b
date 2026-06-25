#pragma once

/**
 * @file macho_rewrite_shared.h
 * @brief Internal helpers shared between the Mach-O rewrite-admission
 *        (`macho_rewrite_admit.c`) and rewrite (`macho_rewrite.c`) layers.
 *
 * This header is a private implementation seam for WP-004/WP-005. It is NOT
 * part of the public Mach-O rewrite API; it exists only to de-duplicate three
 * read-only helpers both translation units need (W-1). The helpers are pure
 * reads of the parsed `n00b_macho_binary_t` / `n00b_macho_layout_t` and never
 * mutate the binary, its stream, or its parsed arrays.
 *
 * Error-layer neutrality: `n00b_macho_rewrite_first_section_start_after`
 * returns the RAW layout error (`N00B_MACHO_LAYOUT_ERR_*`) on failure. Each
 * caller maps that layout error into its own error block (admit `-39xx` via
 * `layout_err_to_admit_err`; rewrite `-44xx`) at the call site. The other two
 * helpers report overflow with the caller-agnostic rewrite overflow code.
 */

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "core/string.h"
#include "compiler/objfile/macho.h"
#include "compiler/objfile/macho_layout.h"
#include "compiler/objfile/macho_rewrite.h"
#include "text/strings/string_ops.h"

// Overflow-safe add used by the shared helpers. Mirrors the per-TU
// `checked_add_u64` (each .c keeps its own for its non-shared arithmetic).
static inline bool
n00b_macho_rewrite_shared_checked_add_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (UINT64_MAX - a < b) {
        return false;
    }

    *out = a + b;
    return true;
}

// True when the segment-command `name` is `__LINKEDIT`. Takes an n00b string
// (callers convert the parsed model's NUL-padded char array at the boundary via
// `n00b_string_from_cstr`) so no `char *` crosses this header (§2.2). Uses
// `r"__LINKEDIT"` rather than an `r"__LINKEDIT"` rstr
// literal: this is a `static inline` in a shared header, and ncc's rstr
// static-object transform does not fire inside an inline header body (it lowers
// to a per-TU `__DATA,n00b_stobj` descriptor). The two forms are
// behavior-equivalent for the comparison.
static inline bool
n00b_macho_segment_name_is_linkedit(n00b_string_t *name)
{
    return n00b_unicode_str_eq(name, r"__LINKEDIT");
}

// Find the smallest first-section file start strictly at/above the load-command
// region end `lc_end`. The LC region can grow downward only until it collides
// with the first segment's section file bytes (mirror `compute_layout` +
// `add_note_insert`, `macho_core.c:256-273,653-660`). Derived from WP-003
// SECTION_FILE intervals via `next_file_interval`, never by re-parsing load
// commands.
//
// Error-layer-neutral: returns the RAW layout error on a `next_file_interval`
// failure, and `Err(N00B_MACHO_LAYOUT_ERR_OVERFLOW)` (the layout layer's own
// overflow code) on a cursor overflow. Callers map the layout error to their
// own error block.
static inline n00b_result_t(n00b_option_t(uint64_t))
n00b_macho_rewrite_first_section_start_after(n00b_macho_layout_t *layout,
                                             uint64_t             lc_end)
{
    n00b_option_t(uint64_t) best   = n00b_option_none(uint64_t);
    uint64_t                cursor = lc_end;

    for (;;) {
        auto next_result = n00b_macho_layout_next_file_interval(layout, cursor);
        if (n00b_result_is_err(next_result)) {
            return n00b_result_err(n00b_option_t(uint64_t),
                                   n00b_result_get_err(next_result));
        }

        n00b_option_t(n00b_macho_layout_interval_t) next_opt =
            n00b_result_get(next_result);
        if (!next_opt.has_value) {
            return n00b_result_ok(n00b_option_t(uint64_t), best);
        }

        n00b_macho_layout_interval_t next = n00b_option_get(next_opt);
        if (next.kind == N00B_MACHO_LAYOUT_INTERVAL_SECTION_FILE
            && next.start >= lc_end) {
            return n00b_result_ok(n00b_option_t(uint64_t),
                                  n00b_option_set(uint64_t, next.start));
        }

        if (next.end <= cursor) {
            if (!n00b_macho_rewrite_shared_checked_add_u64(cursor, 1, &cursor)) {
                return n00b_result_err(n00b_option_t(uint64_t),
                                       N00B_MACHO_LAYOUT_ERR_OVERFLOW);
            }
        }
        else {
            cursor = next.end;
        }
    }
}

// Locate the `__LINKEDIT` segment's file extent and whether it is the highest
// segment file-end (pure reads of the parsed segment array). `*linkedit_offset_out`
// / `*linkedit_end_out` are set to `__LINKEDIT`'s file offset/end (0 if there is
// no `__LINKEDIT` segment); `*have_linkedit_out` records whether one was found.
//
// Error-layer-neutral: returns `Err(N00B_MACHO_LAYOUT_ERR_OVERFLOW)` (the
// layout layer's caller-agnostic overflow code) on a segment-extent overflow,
// so each caller can map it to its own error block exactly as it maps a layout
// overflow.
static inline n00b_result_t(bool)
n00b_macho_rewrite_linkedit_is_last(n00b_macho_binary_t *bin,
                                    uint64_t            *linkedit_offset_out,
                                    uint64_t            *linkedit_end_out,
                                    bool                *have_linkedit_out)
{
    uint64_t max_seg_end   = 0;
    uint64_t linkedit_off  = 0;
    uint64_t linkedit_end  = 0;
    bool     have_linkedit = false;

    for (uint32_t i = 0; i < bin->num_segments; i++) {
        n00b_macho_segment_t *seg = &bin->segments[i];

        uint64_t seg_end;
        if (!n00b_macho_rewrite_shared_checked_add_u64(seg->fileoff,
                                                       seg->filesize,
                                                       &seg_end)) {
            return n00b_result_err(bool, N00B_MACHO_LAYOUT_ERR_OVERFLOW);
        }

        if (seg_end > max_seg_end) {
            max_seg_end = seg_end;
        }

        if (n00b_macho_segment_name_is_linkedit(
                n00b_string_from_cstr(seg->name))) {
            have_linkedit = true;
            linkedit_off  = seg->fileoff;
            linkedit_end  = seg_end;
        }
    }

    *linkedit_offset_out = linkedit_off;
    *linkedit_end_out    = linkedit_end;
    *have_linkedit_out   = have_linkedit;

    return n00b_result_ok(bool, have_linkedit && linkedit_end == max_seg_end);
}
