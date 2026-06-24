/**
 * @file accel.h
 * @brief Acceleration-search dispatchers: minterm and forward-prefix.
 *
 * Internal regex-engine header, not part of the public n00b surface.
 * Names track the upstream Rust `accel` module / resharp-c's `accel.h`
 * closely; the algorithmic vocabulary stays un-prefixed (no `n00b_`)
 * per the regex port convention.
 *
 * Two tagged-union dispatchers live here:
 *
 *  - `MintermSearchValue`  — picks among byte / range / all-match SIMD
 *                            searchers for a single minterm class;
 *  - `FwdPrefixSearch`     — picks among literal / SIMD prefix / range
 *                            searchers for a regex's forward prefix.
 *
 * Both are thin variant wrappers around opaque SIMD-module structures
 * (`RevSearchBytes`, `RevSearchRanges`, `FwdLiteralSearch`,
 * `FwdPrefixSearchSimd`, `FwdRangeSearch`).  The SIMD module owns the
 * concrete layouts and exposes the per-variant `*_find_fwd` /
 * `*_find_rev` / `*_len` entry points declared at the bottom.
 *
 * Companion source: `src/text/regex/engine/accel.c`.
 */
#pragma once

#include "n00b.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "adt/option.h"
#include "adt/list.h"
#include "adt/variant.h"

// ---------------------------------------------------------------------------
// Forward declarations of SIMD-module opaque types.
//
// Phase 10 lands the SIMD subtree under `util/simd/`.  The canonical
// type names carry the `n00b_simd_` prefix; engine-side aliases keep
// the resharp-c shape (`RevTeddySearch`, `FwdLiteralSearch`, …) so the
// algorithmic vocabulary stays intact in this header.
// ---------------------------------------------------------------------------

typedef struct n00b_simd_RevTeddySearch      n00b_simd_RevTeddySearch;
typedef struct n00b_simd_RevSearchBytes      n00b_simd_RevSearchBytes;
typedef struct n00b_simd_RevSearchRanges     n00b_simd_RevSearchRanges;
typedef struct n00b_simd_FwdLiteralSearch    n00b_simd_FwdLiteralSearch;
typedef struct n00b_simd_FwdPrefixSearchSimd n00b_simd_FwdPrefixSearchSimd;
typedef struct n00b_simd_FwdRangeSearch      n00b_simd_FwdRangeSearch;

// Engine-side aliases (unchanged regex algorithmic vocabulary).
typedef n00b_simd_RevTeddySearch      RevTeddySearch;
typedef n00b_simd_RevSearchBytes      RevSearchBytes;
typedef n00b_simd_RevSearchRanges     RevSearchRanges;
typedef n00b_simd_FwdLiteralSearch    FwdLiteralSearch;
typedef n00b_simd_FwdPrefixSearchSimd FwdPrefixSearchSimd;
typedef n00b_simd_FwdRangeSearch      FwdRangeSearch;

// ---------------------------------------------------------------------------
// Match — `(start, end)` byte-offset pair.  Mirrors upstream Rust
// `pub struct Match(pub usize, pub usize)` (`#[repr(C)]`).  Stays
// un-prefixed because it's the regex algorithmic vocabulary.
// ---------------------------------------------------------------------------

/** @brief Half-open byte-offset match range `[start, end)`. */
typedef struct Match {
    size_t start;
    size_t end;
} Match;

// ---------------------------------------------------------------------------
// MintermSearchValue — picks one accelerator per minterm class.
// ---------------------------------------------------------------------------

/** @brief Discriminator tag for `MintermSearchValue`. */
typedef enum MintermSearchValueTag {
    MINTERM_SEARCH_VALUE_EXACT = 0, /**< Exact byte-set search. */
    MINTERM_SEARCH_VALUE_RANGE = 1, /**< Byte-range search. */
    MINTERM_SEARCH_VALUE_ALL   = 2, /**< Every position matches. */
} MintermSearchValueTag;

/**
 * @brief Tagged-union accelerator over a minterm's byte set.
 *
 * Expressed as an `n00b_variant_t` over the two payload-bearing arms
 * (`RevSearchBytes *` for EXACT, `RevSearchRanges *` for RANGE), so the
 * payload pointers are GC-precise / marshalable.  The third logical
 * variant `ALL` (every position matches) carries no payload and is
 * represented by the empty selector (`selector == 0`), constructed via
 * `minterm_search_value_all`.  The payloads are owned by this value
 * (constructed via `minterm_search_value_exact` / `minterm_search_value_range`).
 */
typedef n00b_variant_t(RevSearchBytes *, RevSearchRanges *) MintermSearchValue;

/** @brief Walk @p haystack right-to-left looking for a minterm match. */
[[gnu::always_inline]] static inline n00b_option_t(size_t)
minterm_search_value_find_rev(const MintermSearchValue *self,
                              const uint8_t *haystack, size_t haystack_len);

/** @brief Walk @p haystack left-to-right looking for a minterm match. */
[[gnu::always_inline]] static inline n00b_option_t(size_t)
minterm_search_value_find_fwd(const MintermSearchValue *self,
                              const uint8_t *haystack, size_t haystack_len);

/** @brief Read the variant tag. */
MintermSearchValueTag  minterm_search_value_tag(const MintermSearchValue *self);

/** @brief Borrow the EXACT variant payload, or `nullptr` if not EXACT. */
const RevSearchBytes  *minterm_search_value_exact_bytes(const MintermSearchValue *self);

/** @brief Borrow the RANGE variant payload, or `nullptr` if not RANGE. */
const RevSearchRanges *minterm_search_value_range_ranges(const MintermSearchValue *self);

/** @brief Construct the `ALL` variant (every position matches). */
MintermSearchValue minterm_search_value_all(void);

/** @brief Construct the `EXACT` variant; takes ownership of @p bytes. */
MintermSearchValue minterm_search_value_exact(RevSearchBytes *bytes);

/** @brief Construct the `RANGE` variant; takes ownership of @p ranges. */
MintermSearchValue minterm_search_value_range(RevSearchRanges *ranges);

// ---------------------------------------------------------------------------
// FwdPrefixSearch — picks one accelerator per regex's literal prefix.
// ---------------------------------------------------------------------------

// The former `FwdPrefixSearchTag` discriminator enum is gone: the
// `n00b_variant_t` selector (typehash of the active arm) is the
// discriminator now.  Dispatch with `n00b_variant_is_type` /
// `switch (self->v.selector) { case typehash(FwdLiteralSearch *): ... }`.

/**
 * @brief Tagged-union accelerator over a regex's forward literal prefix.
 *
 * The variant payload is heap-owned by this struct.  Constructors take
 * ownership of the variant payload pointer; `fwd_prefix_search_free`
 * drops the wrapper (the SIMD module is responsible for freeing the
 * variant payload itself before the wrapper is dropped).
 */
// The heap-owned wrapper stays a named `struct FwdPrefixSearch` (it is
// forward-declared as such in bdfa.h and passed around as an opaque
// `FwdPrefixSearch *`), but its discriminated payload is now an
// `n00b_variant_t` over the three payload-bearing arms so the SIMD-search
// pointer is GC-precise / marshalable.  Dispatch on `self->v.selector` /
// `n00b_variant_is_type(self->v, T)`.
typedef struct FwdPrefixSearch {
    n00b_variant_t(FwdLiteralSearch *,
                   FwdPrefixSearchSimd *,
                   FwdRangeSearch *) v;
} FwdPrefixSearch;

/** @brief True iff the variant is `LITERAL`. */
bool   fwd_prefix_search_is_literal(const FwdPrefixSearch *self);

/** @brief Length of the variant's needle / prefix. */
size_t fwd_prefix_search_len(const FwdPrefixSearch *self);

/**
 * @brief Search @p haystack starting at @p start for the first match.
 *
 * Returns the byte offset of the match (relative to the haystack) when
 * found, otherwise none.  Out-of-range @p start (`start > haystack_len`)
 * yields none rather than reading past the buffer.
 */
n00b_option_t(size_t) fwd_prefix_search_find_fwd(const FwdPrefixSearch *self,
                                                 const uint8_t *haystack,
                                                 size_t haystack_len,
                                                 size_t start);

/** @brief Static debug-name for the active variant: "Literal" / "Teddy" / "Range". */
const char *fwd_prefix_search_variant_name(const FwdPrefixSearch *self);

/**
 * @brief Bulk-collect every fixed-length literal match into @p matches.
 *
 * Returns true iff the active variant is `LITERAL` (only that variant
 * supports the bulk path).  Behaviour for other variants: returns false
 * and leaves @p matches untouched.
 */
bool fwd_prefix_search_find_all_literal(const FwdPrefixSearch *self,
                                        const uint8_t *haystack,
                                        size_t haystack_len,
                                        n00b_list_t(Match) *matches);

/** @brief Construct the `LITERAL` variant; takes ownership of non-null @p lit.
 *  @param allocator  Routes wrapper allocation; nullptr → runtime default. */
FwdPrefixSearch *fwd_prefix_search_new_literal(FwdLiteralSearch *lit,
                                               n00b_allocator_t *allocator);

/** @brief Construct the `PREFIX` variant; takes ownership of non-null @p pf. */
FwdPrefixSearch *fwd_prefix_search_new_prefix(FwdPrefixSearchSimd *pf,
                                              n00b_allocator_t *allocator);

/** @brief Construct the `RANGE` variant; takes ownership of non-null @p rng. */
FwdPrefixSearch *fwd_prefix_search_new_range(FwdRangeSearch *rng,
                                             n00b_allocator_t *allocator);

/** @brief Drop the wrapper struct.  Safe with @p p == nullptr. */
void fwd_prefix_search_free(FwdPrefixSearch *p);

// ---------------------------------------------------------------------------
// SIMD-module entry points called from the dispatchers above.
//
// These are declared here (not in a SIMD-private header) so that the
// inline `minterm_search_value_find_*` definitions below are usable in
// any TU including `accel.h`.  The SIMD port (Phase 8) provides the
// definitions.
// ---------------------------------------------------------------------------

extern n00b_option_t(size_t) n00b_simd_rev_search_bytes_find_rev(const RevSearchBytes *s,
                                                                  const uint8_t *haystack,
                                                                  size_t haystack_len);
extern n00b_option_t(size_t) n00b_simd_rev_search_bytes_find_fwd(const RevSearchBytes *s,
                                                                  const uint8_t *haystack,
                                                                  size_t haystack_len);

extern n00b_option_t(size_t) n00b_simd_rev_search_ranges_find_rev(const RevSearchRanges *s,
                                                                   const uint8_t *haystack,
                                                                   size_t haystack_len);
extern n00b_option_t(size_t) n00b_simd_rev_search_ranges_find_fwd(const RevSearchRanges *s,
                                                                   const uint8_t *haystack,
                                                                   size_t haystack_len);

extern n00b_option_t(size_t) n00b_simd_fwd_literal_search_find_fwd(const FwdLiteralSearch *s,
                                                                    const uint8_t *haystack,
                                                                    size_t haystack_len);
extern size_t                n00b_simd_fwd_literal_search_len(const FwdLiteralSearch *s);

// `find_all_fixed` writes `Match` values into the caller-supplied list.
// Upstream Rust transmuted `&mut Vec<Match>` to `&mut Vec<(usize,usize)>`
// because `Match` is `#[repr(C)]`; in the n00b port we just pass the
// typed list directly — no cast required.
extern void                  n00b_simd_fwd_literal_search_find_all_fixed(const FwdLiteralSearch *s,
                                                                          const uint8_t *haystack,
                                                                          size_t haystack_len,
                                                                          n00b_list_t(Match) *out);

extern n00b_option_t(size_t) n00b_simd_fwd_prefix_search_simd_find_fwd(const FwdPrefixSearchSimd *s,
                                                                        const uint8_t *haystack,
                                                                        size_t haystack_len,
                                                                        size_t start);
extern size_t                n00b_simd_fwd_prefix_search_simd_len(const FwdPrefixSearchSimd *s);

extern n00b_option_t(size_t) n00b_simd_fwd_range_search_find_fwd(const FwdRangeSearch *s,
                                                                  const uint8_t *haystack,
                                                                  size_t haystack_len,
                                                                  size_t start);
extern size_t                n00b_simd_fwd_range_search_len(const FwdRangeSearch *s);

// ---------------------------------------------------------------------------
// Inline definitions — kept in the header so the dispatch shrinks to a
// direct branch + tail call at every call site.
// ---------------------------------------------------------------------------

[[gnu::always_inline]] static inline n00b_option_t(size_t)
minterm_search_value_find_rev(const MintermSearchValue *self,
                              const uint8_t *haystack, size_t haystack_len)
{
    switch (self->selector) {
    case typehash(RevSearchBytes *):
        return n00b_simd_rev_search_bytes_find_rev(
            _n00b_variant_get_ptr(self, RevSearchBytes *), haystack, haystack_len);
    case typehash(RevSearchRanges *):
        return n00b_simd_rev_search_ranges_find_rev(
            _n00b_variant_get_ptr(self, RevSearchRanges *), haystack, haystack_len);
    case 0: // ALL — every position matches.
        return n00b_option_set(size_t, 0);
    }
    return n00b_option_none(size_t);
}

[[gnu::always_inline]] static inline n00b_option_t(size_t)
minterm_search_value_find_fwd(const MintermSearchValue *self,
                              const uint8_t *haystack, size_t haystack_len)
{
    switch (self->selector) {
    case typehash(RevSearchBytes *):
        return n00b_simd_rev_search_bytes_find_fwd(
            _n00b_variant_get_ptr(self, RevSearchBytes *), haystack, haystack_len);
    case typehash(RevSearchRanges *):
        return n00b_simd_rev_search_ranges_find_fwd(
            _n00b_variant_get_ptr(self, RevSearchRanges *), haystack, haystack_len);
    case 0: // ALL — find_fwd yields no skip position.
        return n00b_option_none(size_t);
    }
    return n00b_option_none(size_t);
}
