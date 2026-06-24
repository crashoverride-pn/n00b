// SIMD prefilter primitives — aarch64 / NEON backend.
// Phase 10 port from resharp-c/include/simd/neon.h.
//
// External symbols carry the `n00b_simd_` prefix; internal helpers keep
// their resharp-c names per § 5 style-change B.  Algorithmic vocabulary
// (FwdLiteralSearch, RevTeddySearch, …) is preserved in type / accessor
// names so the upstream Rust shape stays readable.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <arm_neon.h>

// `TSet` comes from the algebra side.  Declared opaquely (the SIMD code
// only ever dereferences via `TSet_contains_byte`, a free function).
struct TSet;
typedef struct TSet TSet;

extern bool TSet_contains_byte(const TSet *self, uint8_t b);
extern bool tset_contains_byte(const TSet *self, uint8_t b);

// Byte-frequency table — defined in byte_freq.c.
extern const uint16_t n00b_simd_BYTE_FREQ[256];

// TeddyMasks: pair of 3x32-byte mask tables.
typedef struct n00b_simd_TeddyMasks {
    uint8_t lo[3][32];
    uint8_t hi[3][32];
} n00b_simd_TeddyMasks;

// Rust Option<usize> — modeled as (bool found, size_t value) for the
// internal SIMD ABI.  The accel.h-facing wrappers convert at the
// boundary to `n00b_option_t(size_t)`.
typedef struct {
    bool   found;
    size_t value;
} n00b_simd_OptUsize;

// Rust Vec<(usize, usize)> match list — minimal owning vector.
typedef struct {
    size_t start;
    size_t end;
} n00b_simd_MatchPair;

typedef struct {
    n00b_simd_MatchPair *data;
    size_t               len;
    size_t               cap;
} n00b_simd_MatchVec;

// neon_movemask: collapse a 16-byte all-ones-or-zero compare into a 16-bit
// mask.  Exposed for FwdRangeSearch in mod.c (aarch64 path) plus tests.
uint16_t n00b_simd_neon_movemask(uint8x16_t v);

// ---- RevSearchBytes -------------------------------------------------------

typedef struct n00b_simd_RevSearchBytes {
    uint8_t *bytes;
    size_t   len;
} n00b_simd_RevSearchBytes;

n00b_simd_RevSearchBytes n00b_simd_rev_search_bytes_new_value(const uint8_t *bytes, size_t len);
void                     n00b_simd_rev_search_bytes_free(n00b_simd_RevSearchBytes *s);
const uint8_t           *n00b_simd_rev_search_bytes_bytes(const n00b_simd_RevSearchBytes *s,
                                                          size_t                         *out_len);
n00b_simd_OptUsize       n00b_simd_rev_search_bytes_find_fwd_raw(const n00b_simd_RevSearchBytes *s,
                                                                 const uint8_t                  *haystack,
                                                                 size_t                          hlen);
n00b_simd_OptUsize       n00b_simd_rev_search_bytes_find_rev_raw(const n00b_simd_RevSearchBytes *s,
                                                                 const uint8_t                  *haystack,
                                                                 size_t                          hlen);

// ---- RevSearchRanges ------------------------------------------------------

// `n00b_simd_ByteRange` has `lo`/`hi` field names while the engine-side
// `ByteRange` (solver.h) has `start`/`end`.  The layout is identical
// (`{uint8_t, uint8_t}`); callers reinterpret-cast across the boundary.
typedef struct n00b_simd_ByteRange {
    uint8_t lo;
    uint8_t hi;
} n00b_simd_ByteRange;

typedef struct n00b_simd_RevSearchRanges {
    n00b_simd_ByteRange *ranges;
    size_t               len;
} n00b_simd_RevSearchRanges;

n00b_simd_RevSearchRanges  n00b_simd_rev_search_ranges_new_value(const n00b_simd_ByteRange *ranges,
                                                                 size_t                     len);
void                       n00b_simd_rev_search_ranges_free(n00b_simd_RevSearchRanges *s);
const n00b_simd_ByteRange *n00b_simd_rev_search_ranges_ranges(const n00b_simd_RevSearchRanges *s,
                                                              size_t                          *out_len);
n00b_simd_OptUsize         n00b_simd_rev_search_ranges_find_fwd_raw(const n00b_simd_RevSearchRanges *s,
                                                                    const uint8_t                   *haystack,
                                                                    size_t                           hlen);
n00b_simd_OptUsize         n00b_simd_rev_search_ranges_find_rev_raw(const n00b_simd_RevSearchRanges *s,
                                                                    const uint8_t                   *haystack,
                                                                    size_t                           hlen);

// ---- FwdLiteralSearch -----------------------------------------------------

typedef struct n00b_simd_FwdLiteralSearch {
    uint8_t  *needle;
    size_t    needle_len;
    uint64_t *chunks;
    size_t    chunks_len;
    size_t    rare_idx;
    uint8_t   rare_byte;
    size_t    confirm_idx;
    uint8_t   confirm_byte;
    ptrdiff_t confirm_offset;
} n00b_simd_FwdLiteralSearch;

n00b_simd_FwdLiteralSearch n00b_simd_fwd_literal_search_new_value(const uint8_t *needle,
                                                                  size_t         needle_len);
void                       n00b_simd_fwd_literal_search_free_inner(n00b_simd_FwdLiteralSearch *s);
size_t                     n00b_simd_fwd_literal_search_len(const n00b_simd_FwdLiteralSearch *s);
uint8_t                    n00b_simd_fwd_literal_search_rare_byte(const n00b_simd_FwdLiteralSearch *s);
n00b_simd_OptUsize         n00b_simd_fwd_literal_search_find_fwd_raw(const n00b_simd_FwdLiteralSearch *s,
                                                                     const uint8_t                    *haystack,
                                                                     size_t                            hlen);
void                       n00b_simd_fwd_literal_search_find_all_fixed_raw(const n00b_simd_FwdLiteralSearch *s,
                                                                           const uint8_t                    *haystack,
                                                                           size_t                            hlen,
                                                                           n00b_simd_MatchVec               *matches);

// ---- RevLiteralInner ----------------------------------------------------

typedef struct n00b_simd_RevLiteralInner {
    uint8_t  *needle;
    size_t    needle_len;
    uint64_t *chunks;
    size_t    chunks_len;
    size_t    rare_idx;
    uint8_t   rare_byte;
    size_t    confirm_idx;
    uint8_t   confirm_byte;
    size_t    tail_offset;
} n00b_simd_RevLiteralInner;

// ---- RevTeddyInner ------------------------------------------------------

typedef struct n00b_simd_RevTeddyInner {
    size_t                len;
    size_t                num_simd;
    n00b_simd_TeddyMasks *masks;
    TSet                 *sets;
    size_t                sets_len;
    size_t                tail_offset;
} n00b_simd_RevTeddyInner;

// ---- RevTeddySearch (tagged Teddy/Literal) ------------------------------

typedef enum {
    N00B_SIMD_REV_SEARCH_KIND_TEDDY   = 0,
    N00B_SIMD_REV_SEARCH_KIND_LITERAL = 1,
} n00b_simd_RevSearchKind;

typedef struct n00b_simd_RevTeddySearch {
    n00b_simd_RevSearchKind kind;
    union [[n00b::raw_union]] {
        n00b_simd_RevTeddyInner   teddy;
        n00b_simd_RevLiteralInner literal;
    } u;
} n00b_simd_RevTeddySearch;

n00b_simd_RevTeddySearch n00b_simd_rev_prefix_search_new_value(
    size_t                len,
    const uint8_t *const *byte_sets_raw,
    const size_t         *byte_sets_lens,
    size_t                byte_sets_count,
    TSet                 *all_sets,
    size_t                all_sets_len,
    size_t                tail_offset);

void                     n00b_simd_rev_prefix_search_free(n00b_simd_RevTeddySearch *s);
n00b_simd_RevTeddySearch n00b_simd_rev_prefix_search_add_tail_offset(n00b_simd_RevTeddySearch s,
                                                                     uint32_t                 extra);
size_t                   n00b_simd_rev_prefix_search_len_value(const n00b_simd_RevTeddySearch *s);
n00b_simd_OptUsize       n00b_simd_rev_prefix_search_find_rev_raw(const n00b_simd_RevTeddySearch *s,
                                                                  const uint8_t                  *haystack,
                                                                  size_t                          hlen,
                                                                  size_t                          end);

// ---- FwdPrefixSearch (SIMD-internal Teddy struct) -----------------------

typedef struct n00b_simd_FwdPrefixSearchSimd {
    size_t                len;
    size_t                num_simd;
    size_t                simd_offsets[3];
    n00b_simd_TeddyMasks *masks;
    TSet                 *sets;
    size_t                sets_len;
    uint8_t               verify_order[16];
} n00b_simd_FwdPrefixSearchSimd;

n00b_simd_FwdPrefixSearchSimd n00b_simd_fwd_prefix_search_new_value(
    size_t                len,
    const size_t         *freq_order,
    size_t                freq_order_len,
    const uint8_t *const *byte_sets_raw,
    const size_t         *byte_sets_lens,
    size_t                byte_sets_count,
    TSet                 *all_sets,
    size_t                all_sets_len);

void               n00b_simd_fwd_prefix_search_free_inner(n00b_simd_FwdPrefixSearchSimd *s);
size_t             n00b_simd_fwd_prefix_search_len_value(const n00b_simd_FwdPrefixSearchSimd *s);
n00b_simd_OptUsize n00b_simd_fwd_prefix_search_find_fwd_raw(const n00b_simd_FwdPrefixSearchSimd *s,
                                                            const uint8_t                       *haystack,
                                                            size_t                               hlen,
                                                            size_t                               start);
