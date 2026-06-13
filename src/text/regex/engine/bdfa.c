// Rust 8f01936 reorganization that extracted BDFA from
// upstream into its own module.  This file owns the BDFA struct's
// constructors, transition kernels, build-prefix helpers, accessors, and
// the bdfa_scan / bdfa_inner runtime-PREFIX/runtime-ISMATCH dispatcher
// previously in lib.c.
// Helpers shared with LDFA (collect_sets, transition_term, PartitionTree)
// remain in engine.c and are imported via engine.h.

#include "n00b.h"
#include "core/alloc.h"
#include "adt/dict.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "util/assert.h"
#include "util/panic.h"

#include "internal/regex/bdfa.h"
#include "internal/regex/accel.h"   // Match, FwdPrefixSearch tag/accessors
#include "internal/regex/engine.h"  // OptionFwdPrefixSearch / U8Pair / NullStateList,
                                    // collect_sets / transition_term, TSetIdSet_free,
                                    // engine_generate_minterms / engine_minterms_lookup /
                                    // U8Lookup256.
#include "internal/regex/nulls.h"   // NULLABILITY_CENTER
#include "internal/regex/prefix.h"  // TSetIdVec, prefix_calc_potential_start /
                                    // prefix_calc_prefix_sets_inner /
                                    // prefix_SKIP_FREQ_THRESHOLD
#include "internal/regex/solver.h"  // solver_get_set / solver_is_sat /
                                    // solver_collect_bytes / solver_pp_collect_ranges /
                                    // ByteRange / ByteRangeSet

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdckdint.h>
#include <string.h>  // memcpy / memset (D13)

// =============================================================================
// Sibling-module externs.  Mirror engine.c's block — bdfa.c needs the same
// algebra/solver/simd/prefix surface to build prefix searchers and walk
// derivations.  Most are sourced from the included headers above; the
// remainder are extern'd here so the implementations are not forced to
// expose them at header surface.
// =============================================================================

// solver / pp ranges — already declared in `solver.h` (included above).  We
// rely on its `solver_collect_bytes` / `solver_get_set` / `solver_is_sat` /
// `solver_pp_collect_ranges` (returning `ByteRangeSet`) and the `ByteRange`
// element type.

// simd / accel
extern bool      n00b_simd_has_simd(void);
extern uint16_t  n00b_simd_byte_freq(uint8_t b);
extern TSet      tset_from_bytes(const uint8_t *data, size_t len);

extern FwdLiteralSearch     *n00b_simd_FwdLiteralSearch_new(const uint8_t *needle, size_t nlen);
extern uint8_t               n00b_simd_FwdLiteralSearch_rare_byte(const FwdLiteralSearch *l);
extern void                  n00b_simd_FwdLiteralSearch_free(FwdLiteralSearch *l);
extern FwdPrefixSearchSimd  *n00b_simd_FwdPrefixSearch_new(size_t total_len,
                                                  const size_t *freq_order,
                                                  size_t freq_order_len,
                                                  const ByteVec *byte_sets, size_t bs_len,
                                                  const TSet  *all_sets, size_t as_len);
extern FwdRangeSearch       *n00b_simd_FwdRangeSearch_new(size_t n, size_t anchor_pos,
                                                     const uint8_t *lo, const uint8_t *hi,
                                                     size_t ranges_len,
                                                     const TSet *all_sets, size_t as_len);
extern FwdPrefixSearch      *fwd_prefix_search_new_literal(FwdLiteralSearch *l,
                                                            n00b_allocator_t *allocator);
extern FwdPrefixSearch      *fwd_prefix_search_new_prefix (FwdPrefixSearchSimd *p,
                                                            n00b_allocator_t *allocator);
extern FwdPrefixSearch      *fwd_prefix_search_new_range  (FwdRangeSearch *r,
                                                            n00b_allocator_t *allocator);

// =============================================================================
// Small helpers
// =============================================================================

[[noreturn]] static inline void bdfa_capacity_overflow(void)
{
    n00b_panic("bdfa: capacity overflow");
}

static inline size_t safe_mul_sz(size_t a, size_t b)
{
    size_t r;
    if (ckd_mul(&r, a, b)) {
        bdfa_capacity_overflow();
    }
    return r;
}

static inline size_t safe_add_sz(size_t a, size_t b)
{
    size_t r;
    if (ckd_add(&r, a, b)) {
        bdfa_capacity_overflow();
    }
    return r;
}

// next_power_of_two().trailing_zeros() — same shape as engine.c's helper.
static inline uint32_t next_pow2_log(size_t n)
{
    if (n <= 1) return 0;
    uint32_t l = 0;
    size_t   v = 1;
    while (v < n) { v <<= 1; l += 1; }
    return l;
}

// =============================================================================
// Local list helpers
//
// The growable buffers below are `n00b_list_t(T)` private (unlocked) lists.
// Read access uses direct field reads (`.data`, `.len`); structural writes
// go through `n00b_list_push` or, for the resize-fill / direct-tail-write
// idioms used by the BDFA scan kernel, through the `_resize_fill` helper
// emitted by the macro below (which mirrors what `n00b_list_push` does
// after `_n00b_list_ensure_cap`).
// =============================================================================

#define BDFA_LIST_RESIZE_IMPL(NAME, ETY)                                     \
    static void NAME##_resize_fill(n00b_list_t(ETY) *v, size_t new_len,      \
                                    ETY fill)                                \
    {                                                                        \
        _n00b_list_write_lock(v);                                            \
        _n00b_list_ensure_cap(v, new_len);                                   \
        for (size_t _i = v->len; _i < new_len; ++_i) v->data[_i] = fill;     \
        v->len = new_len;                                                    \
        _n00b_list_unlock(v);                                                \
    }

BDFA_LIST_RESIZE_IMPL(bdfa_list_u32,    uint32_t)

// solver_collect_bytes adapter — same wrapper engine.c exposes around the
// algebra (uint8_t **, size_t *) ABI.  Returns a ByteVec (the layout the
// SIMD-side `n00b_simd_FwdPrefixSearch_new(..., const ByteVec *byte_sets, ...)`
// ABI consumes; matches the prefix.c call site).  The solver returns a
// freshly-owned buffer that we adopt directly.
static ByteVec bdfa_solver_collect_bytes(const Solver *s, TSetId set)
{
    ByteVec v = {};
    uint8_t *raw = nullptr;
    size_t   raw_len = 0;
    solver_collect_bytes(s, set, &raw, &raw_len);
    v.data = raw;
    v.len  = raw_len;
    v.cap  = raw_len;
    return v;
}

// =============================================================================
// NodeId-keyed dict shim — wraps `n00b_dict_t(NodeId, uint16_t)` with a small
// API mirroring the resharp-c `NodeU16Map_*` calls used in this file.
//
// NodeId is `struct NodeId { uint32_t v; }` — a 4-byte scalar newtype with no
// implicit padding, so `skip_obj_hash = true` yields `n00b_hash_raw(&key, 4)`,
// which is exactly the FxHash-equivalent identity behaviour the upstream uses.
// =============================================================================

typedef n00b_dict_t(NodeId, uint16_t) NodeU16Dict;

static NodeU16Dict *node_u16_dict_new(n00b_allocator_t *allocator)
{
    NodeU16Dict *m = n00b_alloc_with_opts(
        NodeU16Dict, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(m, .skip_obj_hash = true, .allocator = allocator,
                   .scan_kind = N00B_GC_SCAN_KIND_NONE);
    return m;
}

static bool node_u16_dict_get(const NodeU16Dict *m, NodeId k, uint16_t *out)
{
    bool     found;
    NodeId   key = k;
    uint16_t v   = n00b_dict_get((NodeU16Dict *)m, key, &found);
    if (found) *out = v;
    return found;
}

static void node_u16_dict_insert(NodeU16Dict *m, NodeId k, uint16_t v)
{
    NodeId   key = k;
    uint16_t val = v;
    n00b_dict_put(m, key, val);
}

// =============================================================================
// Local constants
// =============================================================================

constexpr uint16_t RARE_BYTE_FREQ_LIMIT = 25000u;

// =============================================================================
// BDFA struct
// =============================================================================
//
// Field layout matches Rust upstream `pub(crate) struct BDFA`.  Externally
// the type is opaque (regex.h forward-declares it; bdfa.h only exports
// accessors).  The `c_struct_unused_pad` member from the Rust definition
// has no C analogue.

struct BDFA {
    NodeId                initial_node;
    n00b_list_t(NodeId)   states;
    NodeU16Dict          *state_map;
    n00b_list_t(uint32_t) table;
    n00b_list_t(uint32_t) match_rel;
    n00b_list_t(uint32_t) match_end_off;
    uint32_t              mt_log;
    n00b_list_t(TSetId)   minterms;
    uint8_t               minterms_lookup[256];
    uint16_t              initial;
    OptionFwdPrefixSearch prefix;
    size_t                prefix_len;
    uint16_t              after_prefix;
};

// =============================================================================
// BDFA implementation
// =============================================================================

void bdfa_drop(BDFA *self)
{
    if (!self) return;
    n00b_list_free(self->states);
    n00b_list_free(self->table);
    n00b_list_free(self->match_rel);
    n00b_list_free(self->match_end_off);
    n00b_list_free(self->minterms);
    // The state_map dict and its entries are GC-managed; drop our wrapper
    // pointer.  No explicit dict free per `dict.h`.
    self->state_map = nullptr;
    self->prefix    = (OptionFwdPrefixSearch){.present = false, .value = nullptr};
}

static FwdPrefixSearch *bdfa_build_prefix_search(const ByteVec *byte_sets_raw,
                                                 size_t bs_len,
                                                 n00b_allocator_t *allocator);

static n00b_result_t(int) bdfa_build_prefix_potential(BDFA *self, RegexBuilder *b,
                                                      NodeId pattern_node)
{
    n00b_result_t(TSetIdVec) res
        = prefix_calc_potential_start(b, pattern_node, 16, 64, false);
    if (n00b_result_is_err(res)) {
        return n00b_result_err(int, n00b_result_get_error(res));
    }
    TSetIdVec sets = n00b_result_get(res);
    if (sets.len == 0) {
        if (sets.data) n00b_free(sets.data);
        return n00b_result_ok(int, 0);
    }
    ByteVec *byte_sets_raw =
        n00b_alloc_array(ByteVec, sets.len);
    for (size_t i = 0; i < sets.len; ++i) {
        byte_sets_raw[i] = bdfa_solver_collect_bytes(regex_builder_solver_ref(b),
                                                     sets.data[i]);
    }
    FwdPrefixSearch *search = bdfa_build_prefix_search(byte_sets_raw, sets.len,
                                                       regex_builder_allocator(b));
    if (!search) {
        for (size_t i = 0; i < sets.len; ++i) {
            if (byte_sets_raw[i].data) n00b_free(byte_sets_raw[i].data);
        }
        n00b_free(byte_sets_raw);
        if (sets.data) n00b_free(sets.data);
        return n00b_result_ok(int, 0);
    }
    self->prefix     = (OptionFwdPrefixSearch){.present = true, .value = search};
    self->prefix_len = sets.len;
    for (size_t i = 0; i < sets.len; ++i) {
        if (byte_sets_raw[i].data) n00b_free(byte_sets_raw[i].data);
    }
    n00b_free(byte_sets_raw);
    if (sets.data) n00b_free(sets.data);
    return n00b_result_ok(int, 0);
}

static FwdPrefixSearch *bdfa_try_build_range_prefix(const ByteVec *byte_sets_raw,
                                                    size_t bs_len,
                                                    size_t anchor_pos,
                                                    n00b_allocator_t *allocator)
{
    const ByteVec *anchor = &byte_sets_raw[anchor_pos];
    uint32_t     freq_sum = 0;
    for (size_t i = 0; i < anchor->len; ++i) {
        freq_sum += (uint32_t)n00b_simd_byte_freq(anchor->data[i]);
    }
    if (freq_sum >= prefix_SKIP_FREQ_THRESHOLD) return nullptr;
    TSet         tset   = tset_from_bytes(anchor->data, anchor->len);
    ByteRangeSet ranges = solver_pp_collect_ranges(&tset);
    if (ranges.len == 0 || ranges.len > 3) {
        ByteRangeSet_free(&ranges);
        return nullptr;
    }
    TSet *all_sets = n00b_alloc_array(TSet, bs_len);
    for (size_t i = 0; i < bs_len; ++i) {
        all_sets[i] = tset_from_bytes(byte_sets_raw[i].data, byte_sets_raw[i].len);
    }
    // Splat `ByteRangeSet` into parallel lo/hi arrays — that's the canonical
    // n00b_simd_FwdRangeSearch_new(...) ABI (matches the prefix.c call site).
    uint8_t *lo = n00b_alloc_array(uint8_t, ranges.len);
    uint8_t *hi = n00b_alloc_array(uint8_t, ranges.len);
    for (size_t i = 0; i < ranges.len; ++i) {
        lo[i] = ranges.data[i].start;
        hi[i] = ranges.data[i].end;
    }
    // Allocate the FwdRangeSearch in the same per-regex arena as the
    // FwdPrefixSearch wrapper (see prefix.c) so their lifetimes match and the
    // GC can't reclaim the search struct out from under as.range.
    n00b_allocator_t *prev_alloc = n00b_set_current_allocator(allocator);
    FwdRangeSearch   *r          = n00b_simd_FwdRangeSearch_new(bs_len, anchor_pos,
                                                      lo, hi, ranges.len,
                                                      all_sets, bs_len);
    n00b_restore_current_allocator(prev_alloc);
    n00b_free(lo);
    n00b_free(hi);
    ByteRangeSet_free(&ranges);
    n00b_free(all_sets);
    return fwd_prefix_search_new_range(r, allocator);
}

static FwdPrefixSearch *bdfa_build_prefix_search(const ByteVec *byte_sets_raw,
                                                 size_t bs_len,
                                                 n00b_allocator_t *allocator)
{
    bool all_singletons = true;
    for (size_t i = 0; i < bs_len; ++i) {
        if (byte_sets_raw[i].len != 1) { all_singletons = false; break; }
    }
    if (all_singletons) {
        uint8_t *needle = n00b_alloc_array(uint8_t, bs_len);
        for (size_t i = 0; i < bs_len; ++i) needle[i] = byte_sets_raw[i].data[0];
        n00b_allocator_t *prev_alloc_lit = n00b_set_current_allocator(allocator);
        FwdLiteralSearch *lit = n00b_simd_FwdLiteralSearch_new(needle, bs_len);
        n00b_restore_current_allocator(prev_alloc_lit);
        n00b_free(needle);
        if (!lit) {
            return nullptr;
        }
        if ((uint16_t)n00b_simd_byte_freq(n00b_simd_FwdLiteralSearch_rare_byte(lit))
            >= RARE_BYTE_FREQ_LIMIT) {
            n00b_simd_FwdLiteralSearch_free(lit);
            return nullptr;
        }
        return fwd_prefix_search_new_literal(lit, allocator);
    }

    typedef struct FreqEntry { size_t i; uint64_t f; } FreqEntry;
    FreqEntry *freqs     = n00b_alloc_array(FreqEntry, bs_len);
    size_t     freqs_len = 0;
    for (size_t i = 0; i < bs_len; ++i) {
        uint64_t f = 0;
        for (size_t k = 0; k < byte_sets_raw[i].len; ++k) {
            f += (uint64_t)n00b_simd_byte_freq(byte_sets_raw[i].data[k]);
        }
        if (f > 0) freqs[freqs_len++] = (FreqEntry){.i = i, .f = f};
    }
    if (freqs_len == 0) {
        n00b_free(freqs);
        return nullptr;
    }
    // sort by f ascending (insertion sort — small bounded `bs_len`).
    for (size_t i = 1; i < freqs_len; ++i) {
        FreqEntry x = freqs[i];
        size_t    j = i;
        while (j > 0 && freqs[j - 1].f > x.f) {
            freqs[j] = freqs[j - 1];
            --j;
        }
        freqs[j] = x;
    }
    size_t rarest_idx = freqs[0].i;
    if (byte_sets_raw[rarest_idx].len > 16) {
        FwdPrefixSearch *r = bdfa_try_build_range_prefix(byte_sets_raw, bs_len, rarest_idx, allocator);
        n00b_free(freqs);
        return r;
    }
    size_t *freq_order = n00b_alloc_array(size_t, freqs_len);
    for (size_t i = 0; i < freqs_len; ++i) freq_order[i] = freqs[i].i;
    TSet *all_sets = n00b_alloc_array(TSet, bs_len);
    for (size_t i = 0; i < bs_len; ++i) {
        all_sets[i] = tset_from_bytes(byte_sets_raw[i].data, byte_sets_raw[i].len);
    }
    FwdPrefixSearchSimd *p = n00b_simd_FwdPrefixSearch_new(bs_len, freq_order, freqs_len,
                                                      byte_sets_raw, bs_len,
                                                      all_sets, bs_len);
    n00b_free(freqs);
    n00b_free(freq_order);
    n00b_free(all_sets);
    return fwd_prefix_search_new_prefix(p, allocator);
}

uint32_t bdfa_counted_best(NodeId node, const RegexBuilder *b)
{
    return regex_builder_get_extra(b, node) >> 16;
}

static uint16_t bdfa_register(BDFA *self, NodeId node, const RegexBuilder *b)
{
    uint16_t sid;
    if (node_u16_dict_get(self->state_map, node, &sid)) return sid;
    sid = (uint16_t)self->states.len;
    uint32_t match_step = 0;
    uint32_t match_best = 0;
    NodeId   cur        = node;
    while (cur.v > NODE_ID_BOT.v) {
        n00b_require(regex_builder_get_kind(b, cur) == KIND_COUNTED,
                     "bdfa_register: chain element must be KIND_COUNTED");
        NodeId body = nodeid_left(cur, b);
        if (nodeid_eq(body, NODE_ID_BOT)) {
            uint32_t best = bdfa_counted_best(cur, b);
            if (best > match_best) {
                uint32_t packed = regex_builder_get_extra(b, cur);
                match_step = packed & 0xFFFFu;
                match_best = best;
            }
        }
        cur = nodeid_right(cur, b);
    }
    n00b_list_push(self->states, node);
    node_u16_dict_insert(self->state_map, node, sid);
    n00b_list_push(self->match_rel, match_step);
    n00b_list_push(self->match_end_off, match_step - match_best);
    size_t add = (size_t)1 << self->mt_log;
    bdfa_list_u32_resize_fill(&self->table, safe_add_sz(self->table.len, add), 0u);
    return sid;
}

static n00b_result_t(int) bdfa_derive_chain(RegexBuilder *b, NodeId head, TSetId mt,
                                            n00b_list_t(NodeId) *out)
{
    NodeId cur = head;
    while (cur.v > NODE_ID_BOT.v) {
        n00b_require(regex_builder_get_kind(b, cur) == KIND_COUNTED,
                     "bdfa_derive_chain: chain element must be KIND_COUNTED");
        NodeId chain = nodeid_right(cur, b);
        NodeId body  = nodeid_left(cur, b);
        if (nodeid_eq(body, NODE_ID_BOT)) {
            if (bdfa_counted_best(cur, b) > 0) n00b_list_push(*out, cur);
            cur = chain;
            continue;
        }
        n00b_result_t(TRegexId) der_r = regex_builder_der(b, cur, NULLABILITY_CENTER);
        if (n00b_result_is_err(der_r)) {
            return n00b_result_err(int, n00b_result_get_error(der_r));
        }
        TRegexId der  = n00b_result_get(der_r);
        NodeId   next = transition_term(b, der, mt);
        if (!nodeid_eq(next, NODE_ID_BOT)) n00b_list_push(*out, next);
        cur = chain;
    }
    return n00b_result_ok(int, 0);
}

static NodeId bdfa_rebuild_chain(RegexBuilder *b, const NodeId *cands, size_t len)
{
    NodeId chain = NODE_ID_MISSING;
    for (size_t k = len; k > 0; --k) {
        NodeId   node   = cands[k - 1];
        NodeId   body   = nodeid_left(node, b);
        uint32_t packed = regex_builder_get_extra(b, node);
        NodeId   next   = regex_builder_mk_counted(b, body, chain, packed);
        if (!nodeid_eq(next, NODE_ID_BOT)) chain = next;
    }
    return chain;
}

[[gnu::cold]] [[gnu::noinline]]
static n00b_result_t(uint32_t) bdfa_transition_slow(BDFA *self, RegexBuilder *b,
                                                    uint16_t state, size_t mt_idx)
{
    NodeId head = self->states.data[state];
    TSetId mt   = self->minterms.data[mt_idx];

    n00b_list_t(NodeId) candidates = n00b_list_new_private(NodeId, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    {
        n00b_result_t(int) r = bdfa_derive_chain(b, head, mt, &candidates);
        if (n00b_result_is_err(r)) {
            n00b_list_free(candidates);
            return n00b_result_err(uint32_t, n00b_result_get_error(r));
        }
    }
    n00b_result_t(TRegexId) spawn_der_r
        = regex_builder_der(b, self->initial_node, NULLABILITY_CENTER);
    if (n00b_result_is_err(spawn_der_r)) {
        n00b_list_free(candidates);
        return n00b_result_err(uint32_t, n00b_result_get_error(spawn_der_r));
    }
    TRegexId spawn_der  = n00b_result_get(spawn_der_r);
    NodeId   spawn_next = transition_term(b, spawn_der, mt);
    if (!nodeid_eq(spawn_next, NODE_ID_BOT)) {
        bool present = false;
        for (size_t i = 0; i < candidates.len; ++i) {
            if (nodeid_eq(candidates.data[i], spawn_next)) { present = true; break; }
        }
        if (!present) n00b_list_push(candidates, spawn_next);
    }

    NodeId   new_head = bdfa_rebuild_chain(b, candidates.data, candidates.len);
    uint16_t next_sid = bdfa_register(self, new_head, b);

    uint32_t rel    = self->match_rel.data[next_sid];
    uint32_t packed = (rel << 16) | (uint32_t)next_sid;
    size_t   delta  = ((size_t)state << self->mt_log) | mt_idx;
    self->table.data[delta] = packed;
    n00b_list_free(candidates);
    return n00b_result_ok(uint32_t, packed);
}

[[gnu::always_inline]] inline
n00b_result_t(uint32_t) bdfa_transition(BDFA *self, RegexBuilder *b,
                                        uint16_t state, size_t mt_idx)
{
    size_t   delta  = ((size_t)state << self->mt_log) | mt_idx;
    uint32_t cached = self->table.data[delta];
    if (cached != 0) {
        return n00b_result_ok(uint32_t, cached);
    }
    return bdfa_transition_slow(self, b, state, mt_idx);
}

static n00b_result_t(int) bdfa_build_prefix(BDFA *self, RegexBuilder *b,
                                            NodeId pattern_node)
{
    if (!n00b_simd_has_simd()) return n00b_result_ok(int, 0);
    n00b_result_t(TSetIdVec) res = prefix_calc_prefix_sets_inner(b, pattern_node, false);
    if (n00b_result_is_err(res)) {
        return n00b_result_err(int, n00b_result_get_error(res));
    }
    TSetIdVec prefix_sets = n00b_result_get(res);
    if (prefix_sets.len > 16) prefix_sets.len = 16;
    if (prefix_sets.len == 0) {
        if (prefix_sets.data) n00b_free(prefix_sets.data);
        return bdfa_build_prefix_potential(self, b, pattern_node);
    }

    ByteVec *byte_sets_raw =
        n00b_alloc_array(ByteVec, prefix_sets.len);
    for (size_t i = 0; i < prefix_sets.len; ++i) {
        byte_sets_raw[i] = bdfa_solver_collect_bytes(regex_builder_solver_ref(b),
                                                     prefix_sets.data[i]);
    }

    bool any_multi = false;
    for (size_t i = 0; i < prefix_sets.len; ++i) {
        if (byte_sets_raw[i].len > 1) { any_multi = true; break; }
    }
    if (prefix_sets.len < 3 && any_multi) {
        for (size_t i = 0; i < prefix_sets.len; ++i) {
            if (byte_sets_raw[i].data) n00b_free(byte_sets_raw[i].data);
        }
        n00b_free(byte_sets_raw);
        if (prefix_sets.data) n00b_free(prefix_sets.data);
        return bdfa_build_prefix_potential(self, b, pattern_node);
    }

    FwdPrefixSearch *search = bdfa_build_prefix_search(byte_sets_raw, prefix_sets.len,
                                                       regex_builder_allocator(b));
    if (!search) {
        for (size_t i = 0; i < prefix_sets.len; ++i) {
            if (byte_sets_raw[i].data) n00b_free(byte_sets_raw[i].data);
        }
        n00b_free(byte_sets_raw);
        if (prefix_sets.data) n00b_free(prefix_sets.data);
        return bdfa_build_prefix_potential(self, b, pattern_node);
    }

    uint16_t state = self->initial;
    for (size_t k = 0; k < prefix_sets.len; ++k) {
        TSetId set       = prefix_sets.data[k];
        size_t found_idx = SIZE_MAX;
        TSet   prefix_set = solver_get_set(regex_builder_solver_ref(b), set);
        for (size_t mi = 0; mi < self->minterms.len; ++mi) {
            TSet mt_set = solver_get_set(regex_builder_solver_ref(b),
                                         self->minterms.data[mi]);
            if (solver_is_sat(&mt_set, &prefix_set)) { found_idx = mi; break; }
        }
        if (found_idx == SIZE_MAX) {
            // shouldn't happen — bail successfully
            for (size_t i = 0; i < prefix_sets.len; ++i) {
                if (byte_sets_raw[i].data) n00b_free(byte_sets_raw[i].data);
            }
            n00b_free(byte_sets_raw);
            if (prefix_sets.data) n00b_free(prefix_sets.data);
            return n00b_result_ok(int, 0);
        }
        n00b_result_t(uint32_t) tr = bdfa_transition(self, b, state, found_idx);
        if (n00b_result_is_err(tr)) {
            for (size_t i = 0; i < prefix_sets.len; ++i) {
                if (byte_sets_raw[i].data) n00b_free(byte_sets_raw[i].data);
            }
            n00b_free(byte_sets_raw);
            if (prefix_sets.data) n00b_free(prefix_sets.data);
            return n00b_result_err(int, n00b_result_get_error(tr));
        }
        state = (uint16_t)(n00b_result_get(tr) & 0xFFFFu);
    }
    self->prefix       = (OptionFwdPrefixSearch){.present = true, .value = search};
    self->prefix_len   = prefix_sets.len;
    self->after_prefix = state;

    for (size_t i = 0; i < prefix_sets.len; ++i) {
        if (byte_sets_raw[i].data) n00b_free(byte_sets_raw[i].data);
    }
    n00b_free(byte_sets_raw);
    if (prefix_sets.data) n00b_free(prefix_sets.data);
    return n00b_result_ok(int, 0);
}

n00b_result_t(BDFA *) bdfa_new(RegexBuilder *b, NodeId pattern_node)
{
    n00b_allocator_t *alloc = regex_builder_allocator(b);
    BDFA  *bd            = n00b_alloc_with_opts(
        BDFA, &(n00b_alloc_opts_t){.allocator = alloc});
    bd->states        = n00b_list_new_private(NodeId, .allocator = alloc, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    bd->table         = n00b_list_new_private(uint32_t, .allocator = alloc, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    bd->match_rel     = n00b_list_new_private(uint32_t, .allocator = alloc, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    bd->match_end_off = n00b_list_new_private(uint32_t, .allocator = alloc, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    NodeId initial_node  = regex_builder_mk_counted(b, pattern_node, NODE_ID_MISSING, 0);
    TSetIdSet *sets_set  = collect_sets(b, initial_node);
    bd->minterms         = engine_generate_minterms(sets_set, regex_builder_solver(b));
    TSetIdSet_free(sets_set);

    // Same defensive guard as in engine_LDFA_new_inner; see todo item #17.
    n00b_require(bd->minterms.len > 0,
                 "bdfa_new: minterms must be non-empty");

    U8Lookup256 mt_lookup = engine_minterms_lookup(&bd->minterms, regex_builder_solver(b));
    size_t      num_mt    = bd->minterms.len;
    uint32_t    mt_log    = next_pow2_log(num_mt);
    size_t      stride    = (size_t)1 << mt_log;

    bd->initial_node = initial_node;
    n00b_list_push(bd->states, NODE_ID_MISSING);
    n00b_list_push(bd->states, NODE_ID_MISSING);
    bd->state_map    = node_u16_dict_new(regex_builder_allocator(b));
    bdfa_list_u32_resize_fill(&bd->table, safe_mul_sz(stride, 2), 0u);
    n00b_list_push(bd->match_rel, 0u);
    n00b_list_push(bd->match_rel, 0u);
    n00b_list_push(bd->match_end_off, 0u);
    n00b_list_push(bd->match_end_off, 0u);
    bd->mt_log = mt_log;
    memcpy(bd->minterms_lookup, mt_lookup.v, 256);
    bd->initial      = 1;
    bd->prefix       = (OptionFwdPrefixSearch){.present = false, .value = nullptr};
    bd->prefix_len   = 0;
    bd->after_prefix = 1;

    node_u16_dict_insert(bd->state_map, NODE_ID_MISSING, 1);
    n00b_result_t(int) r = bdfa_build_prefix(bd, b, pattern_node);
    if (n00b_result_is_err(r)) {
        bdfa_drop(bd);
        n00b_free(bd);
        return n00b_result_err(BDFA *, n00b_result_get_error(r));
    }
    return n00b_result_ok(BDFA *, bd);
}

// =============================================================================
// BDFA destructor and accessors
// =============================================================================

void bdfa_free(BDFA *self)
{
    if (!self) return;
    bdfa_drop(self);
    n00b_free(self);
}

const uint32_t *bdfa_table          (const BDFA *bd) { return bd->table.data; }
const uint8_t  *bdfa_minterms_lookup(const BDFA *bd) { return bd->minterms_lookup; }
const uint32_t *bdfa_match_end_off  (const BDFA *bd) { return bd->match_end_off.data; }
const uint32_t *bdfa_match_rel      (const BDFA *bd) { return bd->match_rel.data; }
const NodeId   *bdfa_states         (const BDFA *bd) { return bd->states.data; }
uint32_t        bdfa_mt_log         (const BDFA *bd) { return bd->mt_log; }
uint16_t        bdfa_initial        (const BDFA *bd) { return bd->initial; }
uint16_t        bdfa_after_prefix   (const BDFA *bd) { return bd->after_prefix; }
uint32_t        bdfa_prefix_len     (const BDFA *bd) { return (uint32_t)bd->prefix_len; }

FwdPrefixSearch *bdfa_prefix_get(const BDFA *bd)
{
    return bd->prefix.present ? bd->prefix.value : nullptr;
}

bool bdfa_prefix_is_some(const BDFA *bd) { return bd->prefix.present; }

// bdfa_prefix_is_literal / bdfa_prefix_find_fwd — delegate to accel.h's
// FwdPrefixSearch accessors (which return n00b_option_t(size_t)).
bool bdfa_prefix_is_literal(const BDFA *bd)
{
    if (!bd->prefix.present) return false;
    return fwd_prefix_search_is_literal(bd->prefix.value);
}

bool bdfa_prefix_find_fwd(const BDFA *bd, const uint8_t *input,
                          size_t input_len, size_t pos, size_t *out_pos)
{
    if (!bd->prefix.present) return false;
    n00b_option_t(size_t) r
        = fwd_prefix_search_find_fwd(bd->prefix.value, input, input_len, pos);
    if (!r.has_value) return false;
    *out_pos = r.value;
    return true;
}

// =============================================================================
// Match-list scratch helpers — `n00b_list_t(Match)` exposes data/len/cap, but
// public push routes through a write-locked macro that performs grow-on-demand
// per element.  The scan kernel reserves bulk space up-front and then writes
// directly into the pre-reserved tail; these helpers do the manual grow with
// `n00b_alloc_array`+`memcpy`+`n00b_free` (D13).
// =============================================================================

static void match_list_reserve(n00b_list_t(Match) *m, size_t additional)
{
    size_t need = safe_add_sz(m->len, additional);
    if (need <= m->cap) return;
    size_t newcap = m->cap == 0 ? 16 : m->cap * 2;
    if (newcap < need) newcap = need;
    Match *nd = n00b_alloc_array(Match, newcap);
    if (m->len > 0 && m->data != nullptr) {
        memcpy(nd, m->data, m->len * sizeof(Match));
    }
    if (m->data) n00b_free(m->data);
    m->data = nd;
    m->cap  = newcap;
}

static inline void match_list_push(n00b_list_t(Match) *m, Match v)
{
    if (m->len == m->cap) {
        match_list_reserve(m, 1);
    }
    m->data[m->len++] = v;
}

// =============================================================================
// bdfa_inner / bdfa_scan — runtime-PREFIX / runtime-ISMATCH dispatch kernel
// extracted from lib.c.  In Rust this was
// `bdfa_scan<const PREFIX: u8, const ISMATCH: bool>` calling
// `bdfa_inner<const PREFIX: u8>`; we pass both flags as runtime args.
// =============================================================================

typedef struct BdfaInnerResult {
    uint16_t state;
    size_t   pos;
    size_t   mc;
} BdfaInnerResult;

[[gnu::noinline]]
static BdfaInnerResult bdfa_inner(uint8_t prefix_mode,
                                  const uint32_t *table,
                                  const uint8_t  *ml,
                                  const uint8_t  *data,
                                  uint32_t        mt_log,
                                  uint16_t        initial,
                                  const uint32_t *match_end_off,
                                  uint16_t        state,
                                  size_t          pos,
                                  size_t          len,
                                  Match          *match_buf,
                                  size_t          match_cap)
{
    size_t mc = 0;
    while (pos < len) {
        if (prefix_mode != PREFIX_NONE && state == initial) {
            return (BdfaInnerResult){state, pos, mc};
        }
        size_t   mt    = (size_t)ml[data[pos]];
        size_t   delta = ((size_t)state << mt_log) | mt;
        uint32_t entry = table[delta];
        if (entry == 0) {
            return (BdfaInnerResult){state, pos, mc};
        }
        uint32_t rel = entry >> 16;
        state = (uint16_t)(entry & 0xFFFF);
        if (rel > 0) {
            if (mc >= match_cap) {
                return (BdfaInnerResult){state, pos, mc};
            }
            uint32_t end_off = match_end_off[state];
            size_t   end     = pos + 1 - (size_t)end_off;
            match_buf[mc] = (Match){
                .start = pos + 1 - (size_t)rel,
                .end   = end,
            };
            mc += 1;
            state = initial;
            pos   = end;
            continue;
        }
        pos += 1;
    }
    return (BdfaInnerResult){state, pos, mc};
}

n00b_result_t(bool) bdfa_scan(uint8_t prefix_mode, bool is_match,
                              BDFA *bounded, RegexBuilder *b,
                              const uint8_t *input, size_t len,
                              n00b_list_t(Match) *matches)
{
    bool out_found = false;

    uint16_t       initial = bdfa_initial(bounded);
    uint32_t       mt_log  = bdfa_mt_log(bounded);
    const uint8_t *ml      = bdfa_minterms_lookup(bounded);
    uint16_t       state   = initial;
    size_t         pos     = 0;

    if (prefix_mode == PREFIX_NONE) {
        const uint8_t *data = input;
        if (!is_match) match_list_reserve(matches, 2048);
        for (;;) {
            if (!is_match && matches->len == matches->cap) {
                size_t add = matches->cap > 256 ? matches->cap : 256;
                match_list_reserve(matches, add);
            }
            size_t          spare   = is_match ? 1 : (matches->cap - matches->len);
            Match          *buf_ptr = matches->data + matches->len;
            const uint32_t *table   = bdfa_table(bounded);
            const uint32_t *meo     = bdfa_match_end_off(bounded);

            BdfaInnerResult ir = bdfa_inner(PREFIX_NONE, table, ml, data,
                                            mt_log, initial, meo,
                                            state, pos, len, buf_ptr, spare);
            state = ir.state;
            pos   = ir.pos;
            if (is_match && ir.mc > 0) {
                return n00b_result_ok(bool, true);
            }
            matches->len += ir.mc;
            if (pos >= len) break;

            size_t mt = (size_t)ml[input[pos]];
            n00b_result_t(uint32_t) tr = bdfa_transition(bounded, b, state, mt);
            if (n00b_result_is_err(tr)) {
                return n00b_result_err(bool, n00b_result_get_error(tr));
            }
            uint32_t entry = n00b_result_get(tr);
            state = (uint16_t)(entry & 0xFFFF);
            uint32_t rel = entry >> 16;
            if (rel > 0) {
                if (is_match) {
                    return n00b_result_ok(bool, true);
                }
                uint32_t end_off = bdfa_match_end_off(bounded)[state];
                match_list_push(matches, (Match){
                    .start = pos + 1 - (size_t)rel,
                    .end   = pos + 1 - (size_t)end_off,
                });
                state = initial;
            }
            else {
                pos += 1;
            }
        }
    }
    else {
        // PREFIX_SEARCH / PREFIX_LITERAL
        for (;;) {
            if (pos >= len) break;

            if (state == initial) {
                size_t found_pos;
                if (!bdfa_prefix_find_fwd(bounded, input, len, pos, &found_pos)) {
                    break; // None
                }
                if (prefix_mode == PREFIX_LITERAL) {
                    pos   = found_pos + (size_t)bdfa_prefix_len(bounded);
                    state = bdfa_after_prefix(bounded);
                }
                else {
                    pos = found_pos;
                    uint32_t plen = bdfa_prefix_len(bounded);
                    for (uint32_t i = 0; i < plen; ++i) {
                        if (pos >= len) break;
                        size_t          mt    = (size_t)ml[input[pos]];
                        size_t          delta = ((size_t)state << mt_log) | mt;
                        const uint32_t *table = bdfa_table(bounded);
                        uint32_t        entry = table[delta];
                        if (entry == 0) {
                            n00b_result_t(uint32_t) tr
                                = bdfa_transition(bounded, b, state, mt);
                            if (n00b_result_is_err(tr)) {
                                return n00b_result_err(bool,
                                                       n00b_result_get_error(tr));
                            }
                            entry = n00b_result_get(tr);
                        }
                        state = (uint16_t)(entry & 0xFFFF);
                        if (state == initial) break;
                        pos += 1;
                    }
                }
                uint32_t rel = bdfa_match_rel(bounded)[state];
                if (rel > 0) {
                    if (is_match) {
                        return n00b_result_ok(bool, true);
                    }
                    uint32_t end_off = bdfa_match_end_off(bounded)[state];
                    match_list_push(matches, (Match){
                        .start = pos - (size_t)rel + 1,
                        .end   = pos - (size_t)end_off + 1,
                    });
                    state = initial;
                }
                continue;
            }

            // Inner tight loop
            {
                const uint32_t *table  = bdfa_table(bounded);
                const uint8_t  *data   = input;
                const uint8_t  *ml_ptr = ml;
                const uint32_t *meo    = bdfa_match_end_off(bounded);
                bool restart_outer = false;
                while (pos < len) {
                    size_t   mt    = (size_t)ml_ptr[data[pos]];
                    size_t   delta = ((size_t)state << mt_log) | mt;
                    uint32_t entry = table[delta];
                    if (entry == 0) break;
                    uint32_t rel = entry >> 16;
                    state = (uint16_t)(entry & 0xFFFF);
                    if (state == initial) { restart_outer = true; break; }
                    if (rel > 0) {
                        if (is_match) {
                            return n00b_result_ok(bool, true);
                        }
                        uint32_t end_off = meo[state];
                        match_list_push(matches, (Match){
                            .start = pos + 1 - (size_t)rel,
                            .end   = pos + 1 - (size_t)end_off,
                        });
                        state         = initial;
                        restart_outer = true;
                        break;
                    }
                    pos += 1;
                }
                if (restart_outer) continue;
            }

            if (pos >= len) break;
            size_t mt = (size_t)ml[input[pos]];
            n00b_result_t(uint32_t) tr = bdfa_transition(bounded, b, state, mt);
            if (n00b_result_is_err(tr)) {
                return n00b_result_err(bool, n00b_result_get_error(tr));
            }
            uint32_t entry = n00b_result_get(tr);
            state = (uint16_t)(entry & 0xFFFF);
            uint32_t rel = entry >> 16;
            if (rel > 0) {
                if (is_match) {
                    return n00b_result_ok(bool, true);
                }
                uint32_t end_off = bdfa_match_end_off(bounded)[state];
                size_t   end     = pos + 1 - (size_t)end_off;
                match_list_push(matches, (Match){
                    .start = pos + 1 - (size_t)rel,
                    .end   = end,
                });
                state = initial;
                pos   = end;
            }
            else {
                pos += 1;
            }
        }
    }

    // tail: walk trailing chain to recover best match at end-of-input
    if (state != initial) {
        NodeId node = bdfa_states(bounded)[state];
        if (node.v != NODE_ID_MISSING.v) {
            uint32_t best_val  = 0;
            uint32_t best_step = 0;
            NodeId   cur       = node;
            while (cur.v > NODE_ID_BOT.v) {
                uint32_t packed = regex_builder_get_extra(b, cur);
                uint32_t step   = packed & 0xFFFF;
                uint32_t best   = packed >> 16;
                if (best > best_val) { best_val = best; best_step = step; }
                cur = nodeid_right(cur, b);
            }
            if (best_val > 0) {
                if (is_match) {
                    return n00b_result_ok(bool, true);
                }
                match_list_push(matches, (Match){
                    .start = len - (size_t)best_step,
                    .end   = len - (size_t)best_step + (size_t)best_val,
                });
            }
        }
    }

    return n00b_result_ok(bool, out_found);
}
