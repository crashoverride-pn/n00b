/**
 * @file obj_bundle_arith.h
 * @brief Shared overflow-checked integer/range helpers for the object-bundle
 *        carrier backends.
 *
 * These four pure, allocation-free helpers were originally file-local `static`
 * functions in `obj_bundle.c` (the neutral core + ELF carrier paths). WP-010's
 * Mach-O SPLIT read/reconstruct backend in `obj_bundle_macho.c` needs the same
 * checked arithmetic, and the two live in different translation units, so the
 * helpers are factored here (`static inline`) and consumed by both — replacing
 * what would otherwise be a duplicated copy (refactor-not-duplicate; the names
 * are preserved so existing `obj_bundle.c` call sites are unchanged).
 *
 * All four return `false` on overflow / out-of-range rather than trapping, so
 * callers map the failure to a structured carrier error.
 */
#pragma once

#include "n00b.h"

static inline bool
_n00b_obj_bundle_u64_add(uint64_t a, uint64_t b, uint64_t *out)
{
    if (UINT64_MAX - a < b) {
        return false;
    }

    *out = a + b;
    return true;
}

static inline bool
_n00b_obj_bundle_range_end(uint64_t off, uint64_t len, uint64_t *end)
{
    if (UINT64_MAX - off < len) {
        return false;
    }

    *end = off + len;
    return true;
}

static inline bool
_n00b_obj_bundle_range_within(uint64_t off, uint64_t len, uint64_t total)
{
    uint64_t end = 0;

    return _n00b_obj_bundle_range_end(off, len, &end) && end <= total;
}

static inline bool
_n00b_obj_bundle_ranges_overlap(uint64_t a_off,
                                uint64_t a_len,
                                uint64_t b_off,
                                uint64_t b_len)
{
    uint64_t a_end = 0;
    uint64_t b_end = 0;

    if (!_n00b_obj_bundle_range_end(a_off, a_len, &a_end)
        || !_n00b_obj_bundle_range_end(b_off, b_len, &b_end)) {
        return true;
    }

    return a_off < b_end && b_off < a_end;
}
