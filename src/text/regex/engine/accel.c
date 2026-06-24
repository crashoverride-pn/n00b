#include "n00b.h"
#include "core/alloc.h"
#include "adt/option.h"
#include "adt/list.h"

#include "internal/regex/accel.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ---------------------------------------------------------------------------
// Faithful per-file translation of upstream Rust resharp's `accel`
// dispatcher (resharp-c's `engine/accel.c`).  Two tagged-union wrappers
// fan out to the SIMD-module entry points declared in `accel.h`:
//
//   - `MintermSearchValue` over (EXACT, RANGE, ALL);
//   - `FwdPrefixSearch`    over (LITERAL, PREFIX, RANGE).
//
// All `Option<usize>` returns are `n00b_option_t(size_t)`; allocations
// go through `n00b_alloc(FwdPrefixSearch)`.  No SIMD work happens here.
// ---------------------------------------------------------------------------

// ===========================================================================
// FwdPrefixSearch — variant queries
// ===========================================================================

bool fwd_prefix_search_is_literal(const FwdPrefixSearch *self)
{
    if (!self) return false;
    return n00b_variant_is_type(self->v, FwdLiteralSearch *);
}

size_t fwd_prefix_search_len(const FwdPrefixSearch *self)
{
    if (!self) return 0;
    switch (self->v.selector) {
    case typehash(FwdLiteralSearch *):
        return n00b_simd_fwd_literal_search_len(
            n00b_variant_get(self->v, FwdLiteralSearch *));
    case typehash(FwdPrefixSearchSimd *):
        return n00b_simd_fwd_prefix_search_simd_len(
            n00b_variant_get(self->v, FwdPrefixSearchSimd *));
    case typehash(FwdRangeSearch *):
        return n00b_simd_fwd_range_search_len(
            n00b_variant_get(self->v, FwdRangeSearch *));
    }
    return 0;
}

// Add @p addend to a found offset; pass through `none` unchanged.
[[gnu::always_inline]] static inline n00b_option_t(size_t)
opt_add(n00b_option_t(size_t) o, size_t addend)
{
    if (o.has_value) {
        return n00b_option_set(size_t, o.value + addend);
    }
    return n00b_option_none(size_t);
}

[[gnu::always_inline]]
n00b_option_t(size_t) fwd_prefix_search_find_fwd(const FwdPrefixSearch *self,
                                                 const uint8_t *haystack,
                                                 size_t haystack_len,
                                                 size_t start)
{
    if (!self) {
        return n00b_option_none(size_t);
    }

    // Guard against `start > haystack_len`: Rust's `&haystack[start..]`
    // panics in that case; the C version would silently underflow
    // `haystack_len - start` (size_t wraps near SIZE_MAX) and form an
    // out-of-range pointer `haystack + start`, then pass the bogus length
    // into the SIMD literal searcher (OOB read).  The boundary
    // `start == haystack_len` remains valid (empty slice → no match), so
    // use `>` not `>=`.
    if (start > haystack_len) {
        return n00b_option_none(size_t);
    }
    switch (self->v.selector) {
    case typehash(FwdLiteralSearch *): {
        const uint8_t        *sub     = haystack + start;
        size_t                sub_len = haystack_len - start;
        n00b_option_t(size_t) r       = n00b_simd_fwd_literal_search_find_fwd(
            n00b_variant_get(self->v, FwdLiteralSearch *), sub, sub_len);
        return opt_add(r, start);
    }
    case typehash(FwdPrefixSearchSimd *):
        return n00b_simd_fwd_prefix_search_simd_find_fwd(
            n00b_variant_get(self->v, FwdPrefixSearchSimd *),
            haystack, haystack_len, start);
    case typehash(FwdRangeSearch *):
        return n00b_simd_fwd_range_search_find_fwd(
            n00b_variant_get(self->v, FwdRangeSearch *),
            haystack, haystack_len, start);
    }
    return n00b_option_none(size_t);
}

const char *fwd_prefix_search_variant_name(const FwdPrefixSearch *self)
{
    if (!self) return "";
    switch (self->v.selector) {
    case typehash(FwdLiteralSearch *):    return "Literal";
    case typehash(FwdPrefixSearchSimd *): return "Teddy";
    case typehash(FwdRangeSearch *):      return "Range";
    }
    return "";
}

// Bulk-collect every fixed-length literal match.  Upstream Rust
// transmuted `&mut Vec<Match>` to `&mut Vec<(usize,usize)>` because
// `Match` is `#[repr(C)]`; we pass the typed list straight through.
bool fwd_prefix_search_find_all_literal(const FwdPrefixSearch *self,
                                        const uint8_t *haystack,
                                        size_t haystack_len,
                                        n00b_list_t(Match) *matches)
{
    if (!self) return false;
    switch (self->v.selector) {
    case typehash(FwdLiteralSearch *):
        n00b_simd_fwd_literal_search_find_all_fixed(
            n00b_variant_get(self->v, FwdLiteralSearch *),
            haystack, haystack_len, matches);
        return true;
    default:
        return false;
    }
}

// ===========================================================================
// MintermSearchValue — accessors and constructors.
//
// The struct is `{tag, union as}`; the union owns the variant payload
// (the SIMD-module pointer) so the constructors transfer ownership in
// and the consumers (engine.c / parser callers) drop the payload via
// the SIMD-side free routines when the wrapper is discarded.
// ===========================================================================

MintermSearchValueTag minterm_search_value_tag(const MintermSearchValue *self)
{
    // The ALL variant has no payload and is represented by the empty
    // selector (0); the two payload-bearing arms carry their typehash.
    switch (self->selector) {
    case typehash(RevSearchBytes *):  return MINTERM_SEARCH_VALUE_EXACT;
    case typehash(RevSearchRanges *): return MINTERM_SEARCH_VALUE_RANGE;
    default:                          return MINTERM_SEARCH_VALUE_ALL;
    }
}

const RevSearchBytes *minterm_search_value_exact_bytes(const MintermSearchValue *self)
{
    return n00b_variant_is_type(*self, RevSearchBytes *)
             ? n00b_variant_get(*self, RevSearchBytes *)
             : nullptr;
}

const RevSearchRanges *minterm_search_value_range_ranges(const MintermSearchValue *self)
{
    return n00b_variant_is_type(*self, RevSearchRanges *)
             ? n00b_variant_get(*self, RevSearchRanges *)
             : nullptr;
}

MintermSearchValue minterm_search_value_all(void)
{
    // ALL carries no payload — the empty selector is the ALL discriminant.
    return n00b_variant_empty(MintermSearchValue);
}

MintermSearchValue minterm_search_value_exact(RevSearchBytes *bytes)
{
    return n00b_variant_set(MintermSearchValue, RevSearchBytes *, bytes);
}

MintermSearchValue minterm_search_value_range(RevSearchRanges *ranges)
{
    return n00b_variant_set(MintermSearchValue, RevSearchRanges *, ranges);
}

// ===========================================================================
// FwdPrefixSearch — polymorphic constructors / drop.
//
// Each constructor allocates the wrapper through n00b's typed allocator
// and takes ownership of a non-null variant payload pointer. A null
// payload is rejected with a null wrapper result so backendless SIMD
// stubs cannot be stored inside a live regex accelerator wrapper.
// ===========================================================================

FwdPrefixSearch *fwd_prefix_search_new_literal(FwdLiteralSearch *lit,
                                               n00b_allocator_t *allocator)
{
    if (!lit) return nullptr;

    FwdPrefixSearch *p = n00b_alloc_with_opts(
        FwdPrefixSearch, &(n00b_alloc_opts_t){.allocator = allocator});
    p->v = n00b_variant_set(typeof(p->v), FwdLiteralSearch *, lit);
    return p;
}

FwdPrefixSearch *fwd_prefix_search_new_prefix(FwdPrefixSearchSimd *pf,
                                              n00b_allocator_t *allocator)
{
    if (!pf) return nullptr;

    FwdPrefixSearch *p = n00b_alloc_with_opts(
        FwdPrefixSearch, &(n00b_alloc_opts_t){.allocator = allocator});
    p->v = n00b_variant_set(typeof(p->v), FwdPrefixSearchSimd *, pf);
    return p;
}

FwdPrefixSearch *fwd_prefix_search_new_range(FwdRangeSearch *rng,
                                             n00b_allocator_t *allocator)
{
    if (!rng) return nullptr;

    FwdPrefixSearch *p = n00b_alloc_with_opts(
        FwdPrefixSearch, &(n00b_alloc_opts_t){.allocator = allocator});
    p->v = n00b_variant_set(typeof(p->v), FwdRangeSearch *, rng);
    return p;
}

void fwd_prefix_search_free(FwdPrefixSearch *p)
{
    if (!p) return;
    n00b_free(p);
}
