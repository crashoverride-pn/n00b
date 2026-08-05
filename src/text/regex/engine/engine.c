// engine.c — lazy on-demand DFA for the n00b regex.
//
// Per § 0a-Z: typed translation of upstream Rust resharp `engine`, with
// resharp-c's xalloc / HASHMAP / VEC macro shims and abort-on-failure
// REQUIRE/PANIC_FMT wrappers replaced by their n00b primitives:
//
//   FxHashMap<K, V>          -> n00b_dict_t(K, V) — `skip_obj_hash = true`
//                               for POD keys (NodeId/TSetId/u16) so
//                               n00b_hash_raw drives content equality.
//   HashSet<T>               -> n00b_dict_t(T, bool) with unit-true value
//                               (D11; engine.c never needs union/inter set ops).
//   Vec<T> (cross-TU wire)   -> bare `{T *data; size_t len; size_t cap}`
//                               structs declared in engine.h, grown via
//                               file-local helpers (single-owner; the LDFA
//                               or engine.c itself owns every instance).
//   Vec<T> (per-call match)  -> n00b_list_t(Match) — the public surface
//                               vocabulary; matches the accel.h / public.c
//                               wire format.
//   xalloc shim              -> n00b_alloc_array(T, N) / n00b_free.  Vec
//                               grow is alloc-new + memcpy (D13) + n00b_free.
//   pthread / atomics        -> not used by engine.c (clean — single LDFA
//                               owner discipline).
//   PANIC_FMT                -> n00b_panic(fmt, ...) (D9).
//   REQUIRE / FFI_REQUIRE_*  -> n00b_require(cond, msg) (D8).
//   `Error *` returns        -> n00b_result_t(T) with err side carrying
//                               an `n00b_regex_algebra_err_t` cast to int.
//   ckd_mul_sz / ckd_add_sz  -> <stdckdint.h> directly per § 15(C).
//
// Algorithmic shape and control flow are unchanged from upstream Rust /
// resharp-c.  Specialised monomorphisations of `scan_fwd<SKIP>`,
// `scan_fwd_verify<SKIP>`, `collect_rev<EARLY_EXIT, SKIP, INITIAL_SKIP>`,
// `scan_fwd_first_null<SKIP>` are emitted via [[gnu::always_inline]]
// inner bodies + [[gnu::noinline]] dispatchers, mirroring Rust's
// `<const SKIP: bool>` const-generic dispatch.

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdckdint.h>
#include <string.h> // memcpy / memset / memmove (D13)

#include "n00b.h"
#include "core/alloc.h"
#include "adt/dict.h"
#include "adt/list.h"
#include "adt/result.h"
#include "adt/option.h"
#include "util/assert.h"
#include "util/panic.h"

#include "internal/regex/ids.h"
#include "internal/regex/algebra.h"
#include "internal/regex/nulls.h"
#include "internal/regex/solver.h"
#include "internal/regex/accel.h"
#include "internal/regex/engine.h"

// ===========================================================================
// Sibling-module externs not declared by algebra.h / accel.h / solver.h.
// ===========================================================================

// SIMD module (Phase 8).  Engine code only refers to these by pointer or
// by simple value return — concrete layouts stay opaque.

extern bool     n00b_simd_has_simd(void);
extern uint16_t n00b_simd_byte_freq(uint8_t b);

extern n00b_option_t(size_t) n00b_simd_rev_prefix_search_find_rev(const RevTeddySearch *self,
                                                         const uint8_t *haystack,
                                                         size_t haystack_len,
                                                         size_t pos);

extern RevSearchBytes  *n00b_simd_RevSearchBytes_new (n00b_list_t(uint8_t) bytes);
extern RevSearchRanges *n00b_simd_RevSearchRanges_new(n00b_list_t(U8Pair) ranges);

/** @brief Read a `RevSearchBytes`'s underlying byte buffer (borrowed). */
extern const uint8_t   *n00b_simd_rev_search_bytes_bytes (const RevSearchBytes  *s,
                                                size_t *out_len);

/** @brief Read a `RevSearchRanges`'s underlying range buffer (borrowed).
 *  SIMD-side returns `n00b_simd_ByteRange *`; layout-identical to
 *  engine-side `ByteRange` (both `{uint8_t,uint8_t}`).  Call sites cast. */
struct n00b_simd_ByteRange;
extern const struct n00b_simd_ByteRange *n00b_simd_rev_search_ranges_ranges(
    const RevSearchRanges *s, size_t *out_len);

// FAS module (parallel Phase 7 sibling).
extern n00b_result_t(int) LDFA_scan_fwd_active_set_always_nullable(
    LDFA *self, RegexBuilder *b, FwdDFA *fas,
    const uint8_t *data, size_t data_len,
    const size_t *nulls, size_t nulls_len,
    void *matches);
extern n00b_result_t(int) LDFA_scan_fwd_active_set_general(
    LDFA *self, RegexBuilder *b, FwdDFA *fas,
    const uint8_t *data, size_t data_len,
    const size_t *nulls, size_t nulls_len,
    void *matches);

// ===========================================================================
// Capacity / size helpers — checked-arithmetic wrappers.
// ===========================================================================

[[noreturn]] static inline void
engine_capacity_overflow(void)
{
    n00b_panic("engine.c: capacity overflow");
}

static inline size_t
safe_mul_sz(size_t a, size_t b)
{
    size_t r;
    if (ckd_mul(&r, a, b)) {
        engine_capacity_overflow();
    }
    return r;
}

static inline size_t
safe_add_sz(size_t a, size_t b)
{
    size_t r;
    if (ckd_add(&r, a, b)) {
        engine_capacity_overflow();
    }
    return r;
}

// Geometric grow for a single-owner `T data[]` with `len`/`cap` book-keeping.
// Used only by the Deque helpers below — n00b_list_t handles its own grow.
#define grow_buf(T, p_data, p_cap, old_len, new_cap)                          \
    do {                                                                      \
        size_t _gb_nc  = (new_cap);                                           \
        T     *_gb_new = n00b_alloc_array(T, _gb_nc);                         \
        if ((old_len) > 0 && *(p_data) != nullptr) {                          \
            memcpy(_gb_new, *(p_data),                                        \
                   safe_mul_sz((old_len), sizeof(T)));                        \
        }                                                                     \
        if (*(p_data) != nullptr) {                                           \
            n00b_free(*(p_data));                                             \
        }                                                                     \
        *(p_data) = _gb_new;                                                  \
        *(p_cap)  = _gb_nc;                                                   \
    } while (0)

// ===========================================================================
// Engine-local list helpers (resize-fill).
//
// `n00b_list_t(T)` exposes push/get/set but no public resize-fill; the LDFA
// build path needs both an "extend with constant fill" pattern (for the
// per-state tables) and direct tail writes after a resize.  We emit per-
// element-type wrappers that go through `_n00b_list_ensure_cap` (the same
// path `n00b_list_push` uses internally).
// ===========================================================================

#define ENG_LIST_RESIZE_IMPL(NAME, ETY)                                       \
    static void NAME##_resize_fill(n00b_list_t(ETY) *v, size_t new_len,       \
                                    ETY fill)                                 \
    {                                                                         \
        _n00b_list_write_lock(v);                                             \
        _n00b_list_ensure_cap(v, new_len);                                    \
        for (size_t _i = v->len; _i < new_len; ++_i) v->data[_i] = fill;      \
        v->len = new_len;                                                     \
        _n00b_list_unlock(v);                                                 \
    }

ENG_LIST_RESIZE_IMPL(eng_list_u8,     uint8_t)
ENG_LIST_RESIZE_IMPL(eng_list_u16,    uint16_t)
ENG_LIST_RESIZE_IMPL(eng_list_u32,    uint32_t)
ENG_LIST_RESIZE_IMPL(eng_list_usize,  size_t)

// `next_power_of_two().trailing_zeros()` for usize.
static inline uint32_t
next_pow2_log(size_t n)
{
    if (n <= 1) return 0;
    uint32_t l = 0;
    size_t   v = 1;
    while (v < n) { v <<= 1; l += 1; }
    return l;
}

static inline size_t usize_max(size_t a, size_t b) { return a > b ? a : b; }
static inline size_t usize_min(size_t a, size_t b) { return a < b ? a : b; }

// ===========================================================================
// Algebra-side Error→int helper.  The algebra port uses `n00b_result_t(T)`
// with `n00b_regex_algebra_err_t` cast to int; engine code that consumes
// `regex_builder_der` simply forwards the err code on failure.
// ===========================================================================

static inline int
engine_err_capacity_exceeded(void)
{
    return (int)N00B_REGEX_ALGEBRA_ERR_STATE_SPACE_EXPLOSION;
}

static inline int
engine_err_pattern_too_large(void)
{
    return (int)N00B_REGEX_ALGEBRA_ERR_UNSUPPORTED_PATTERN;
}

// ===========================================================================
// `engine_solver_collect_bytes` / `engine_make_nulls_entry_vec` adapters.
// ===========================================================================

// Algebra `regex_builder_nulls_entry_vec` is a two-call API: the return
// value gives the entry count, and a non-null `out` buffer of size `cap`
// is filled with up to min(n, cap) entries.  Engine wraps it in a helper
// that produces an owned `NullStateList` (private list of NullState).
static NullStateList
engine_make_nulls_entry_vec(const RegexBuilder *b, uint32_t idx)
{
    size_t        n   = regex_builder_nulls_entry_vec(b, idx, nullptr, 0);
    NullStateList out = n00b_list_new_private(NullState,
        .allocator = regex_builder_allocator(b),
        .scan_kind = N00B_GC_SCAN_KIND_NONE);
    if (n > 0) {
        _n00b_list_write_lock(&out);
        _n00b_list_ensure_cap(&out, n);
        out.len = n;
        _n00b_list_unlock(&out);
        (void)regex_builder_nulls_entry_vec(b, idx, out.data, n);
    }
    return out;
}

// Solver's canonical signature is
// `void solver_collect_bytes(const Solver *, TSetId, uint8_t **, size_t *)`.
// Engine wants an unlocked `n00b_list_t(uint8_t)` with the bytes adopted
// into a freeable buffer.
static n00b_list_t(uint8_t)
engine_solver_collect_bytes(const Solver *s, TSetId set)
{
    n00b_list_t(uint8_t) v = n00b_list_new_private(uint8_t,
        .allocator = s ? s->allocator : nullptr,
        .scan_kind = N00B_GC_SCAN_KIND_NONE);
    uint8_t *raw_data = nullptr;
    size_t   raw_len  = 0;
    solver_collect_bytes(s, set, &raw_data, &raw_len);
    if (raw_len > 0 && raw_data) {
        _n00b_list_write_lock(&v);
        _n00b_list_ensure_cap(&v, raw_len);
        memcpy(v.data, raw_data, raw_len);
        v.len = raw_len;
        _n00b_list_unlock(&v);
    }
    return v;
}

// ===========================================================================
// per-node id helpers (Rust used method syntax `node_id.left(b)` etc.).
// ===========================================================================

static inline NodeId
nodeid_left_local(NodeId n, const RegexBuilder *b)
{
    return regex_builder_left(b, n);
}

static inline NodeId
nodeid_right_local(NodeId n, const RegexBuilder *b)
{
    return regex_builder_right(b, n);
}

static inline TSetId
nodeid_pred_tset_local(NodeId n, const RegexBuilder *b)
{
    return regex_builder_pred_tset(b, n);
}

static inline bool
tsetid_eq(TSetId a, TSetId b)
{
    return a.v == b.v;
}

static inline bool
nullsid_eq_local(NullsId a, NullsId b)
{
    return a.v == b.v;
}

// ===========================================================================
// PartitionTree (private to engine.c)
//
// The minterm-generation refinement tree: starts as a single FULL leaf,
// and `refine` recursively splits leaves on each input set so the final
// leaf set is the (TSET_ID_FULL-prefixed) minterm partition.
// ===========================================================================

constexpr uint32_t PARTITION_NO_CHILD = UINT32_MAX;

typedef struct PartitionTree {
    n00b_list_t(TSetId)   sets;
    n00b_list_t(uint32_t) lefts;
    n00b_list_t(uint32_t) rights;
} PartitionTree;

static void
PartitionTree_init(PartitionTree *pt, TSetId set, n00b_allocator_t *allocator)
{
    pt->sets   = n00b_list_new_private(TSetId, .allocator = allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    pt->lefts  = n00b_list_new_private(uint32_t, .allocator = allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    pt->rights = n00b_list_new_private(uint32_t, .allocator = allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_list_push(pt->sets,   set);
    n00b_list_push(pt->lefts,  PARTITION_NO_CHILD);
    n00b_list_push(pt->rights, PARTITION_NO_CHILD);
}

static void
PartitionTree_drop(PartitionTree *pt)
{
    n00b_list_free(pt->sets);
    n00b_list_free(pt->lefts);
    n00b_list_free(pt->rights);
}

static uint32_t
PartitionTree_push(PartitionTree *pt, TSetId set)
{
    uint32_t idx = (uint32_t)pt->sets.len;
    n00b_list_push(pt->sets,   set);
    n00b_list_push(pt->lefts,  PARTITION_NO_CHILD);
    n00b_list_push(pt->rights, PARTITION_NO_CHILD);
    return idx;
}

static void
PartitionTree_refine(PartitionTree *pt, uint32_t idx, TSetId other,
                     Solver *solver)
{
    TSetId set            = pt->sets.data[idx];
    TSetId this_and_other = solver_and_id(solver, set, other);
    if (tsetid_eq(this_and_other, TSET_ID_EMPTY)) return;
    TSetId notother         = solver_not_id(solver, other);
    TSetId this_minus_other = solver_and_id(solver, set, notother);
    if (tsetid_eq(this_minus_other, TSET_ID_EMPTY)) return;
    if (pt->lefts.data[idx] == PARTITION_NO_CHILD) {
        uint32_t l = PartitionTree_push(pt, this_and_other);
        uint32_t r = PartitionTree_push(pt, this_minus_other);
        pt->lefts.data[idx]  = l;
        pt->rights.data[idx] = r;
    }
    else {
        uint32_t l = pt->lefts.data[idx];
        uint32_t r = pt->rights.data[idx];
        PartitionTree_refine(pt, l, other, solver);
        PartitionTree_refine(pt, r, other, solver);
    }
}

static n00b_list_t(TSetId)
PartitionTree_get_leaf_sets(const PartitionTree *pt)
{
    /* Re-use the same allocator the tree's lists were created with. */
    n00b_allocator_t *alloc = pt->sets.allocator;
    n00b_list_t(TSetId)   leaves = n00b_list_new_private(TSetId, .allocator = alloc, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_list_t(uint32_t) stack  = n00b_list_new_private(uint32_t, .allocator = alloc, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_list_push(stack, 0u);
    while (stack.len > 0) {
        uint32_t idx = stack.data[--stack.len];
        if (pt->lefts.data[idx] == PARTITION_NO_CHILD) {
            n00b_list_push(leaves, pt->sets.data[idx]);
        }
        else {
            n00b_list_push(stack, pt->lefts.data[idx]);
            n00b_list_push(stack, pt->rights.data[idx]);
        }
    }
    n00b_list_free(stack);
    return leaves;
}

static int
tsetid_cmp_qsort(const void *a, const void *b)
{
    uint32_t x = ((const TSetId *)a)->v;
    uint32_t y = ((const TSetId *)b)->v;
    return (x > y) - (x < y);
}

// ===========================================================================
// TSetIdSet / NodeIdSet / NodeU16Map / NodeU8Map / NodeUSizeMap / U16Set
//
// Per § 7.5 D11: hash-keyed sets render as `n00b_dict_t(T, bool)` with
// unit-true value; engine.c never needs union/intersection set ops, so
// the bitset path is unnecessary.  All maps use `skip_obj_hash = true`
// so n00b_hash_raw drives content equality on the POD key bits.
// ===========================================================================

typedef n00b_dict_t(TSetId,   bool)     TSetIdSetImpl;
typedef n00b_dict_t(NodeId,   bool)     NodeIdSetImpl;
typedef n00b_dict_t(NodeId,   uint16_t) NodeU16MapImpl;
typedef n00b_dict_t(NodeId,   uint8_t)  NodeU8MapImpl;
typedef n00b_dict_t(NodeId,   size_t)   NodeUSizeMapImpl;
typedef n00b_dict_t(uint16_t, bool)     U16SetImpl;

// `TSetIdSet` and `NodeU16Map` are forward-declared in engine.h with
// opaque tags; the impl structs live here.  Cast through the typed
// dict at the call site.
struct TSetIdSet { TSetIdSetImpl impl; };
struct NodeU16Map { NodeU16MapImpl impl; };

static TSetIdSet *
TSetIdSet_new_alloc(n00b_allocator_t *allocator)
{
    TSetIdSet *s = n00b_alloc_with_opts(
        TSetIdSet, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(&s->impl, .skip_obj_hash = true, .allocator = allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    return s;
}

static TSetIdSet *
TSetIdSet_new(void)
{
    return TSetIdSet_new_alloc(nullptr);
}

void
TSetIdSet_free(TSetIdSet *s)
{
    if (!s) return;
    // The dict's internal storage is GC-managed; just release the wrapper.
    n00b_free(s);
}

static bool
TSetIdSet_insert(TSetIdSet *s, TSetId k)
{
    if (n00b_dict_contains(&s->impl, k)) return false;
    bool t = true;
    n00b_dict_put(&s->impl, k, t);
    return true;
}

// ----- NodeIdSet -----

typedef struct NodeIdSet { NodeIdSetImpl impl; } NodeIdSet;

static NodeIdSet *
NodeIdSet_new_alloc(n00b_allocator_t *allocator)
{
    NodeIdSet *s = n00b_alloc_with_opts(
        NodeIdSet, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(&s->impl, .skip_obj_hash = true, .allocator = allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    return s;
}

static NodeIdSet *
NodeIdSet_new(void)
{
    return NodeIdSet_new_alloc(nullptr);
}

static void
NodeIdSet_free(NodeIdSet *s)
{
    if (!s) return;
    n00b_free(s);
}

static bool
NodeIdSet_insert(NodeIdSet *s, NodeId k)
{
    if (n00b_dict_contains(&s->impl, k)) return false;
    bool t = true;
    n00b_dict_put(&s->impl, k, t);
    return true;
}

static bool
NodeIdSet_contains(NodeIdSet *s, NodeId k)
{
    return n00b_dict_contains(&s->impl, k);
}

static size_t
NodeIdSet_len(NodeIdSet *s)
{
    return (size_t)n00b_dict_internal_len((_n00b_dict_internal_t *)&s->impl);
}

// ----- NodeU16Map -----

static NodeU16Map *
NodeU16Map_new_alloc(n00b_allocator_t *allocator)
{
    NodeU16Map *m = n00b_alloc_with_opts(
        NodeU16Map, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(&m->impl, .skip_obj_hash = true, .allocator = allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    return m;
}

static NodeU16Map *
NodeU16Map_new(void)
{
    return NodeU16Map_new_alloc(nullptr);
}

static void
NodeU16Map_free(NodeU16Map *m)
{
    if (!m) return;
    n00b_free(m);
}

static bool
NodeU16Map_get(NodeU16Map *m, NodeId k, uint16_t *out)
{
    bool     found;
    uint16_t got = n00b_dict_get(&m->impl, k, &found);
    if (found) *out = got;
    return found;
}

static void
NodeU16Map_insert(NodeU16Map *m, NodeId k, uint16_t v)
{
    n00b_dict_put(&m->impl, k, v);
}

// ----- NodeU8Map -----

typedef struct NodeU8MapWrap { NodeU8MapImpl impl; } NodeU8Map;

static NodeU8Map *
NodeU8Map_new_alloc(n00b_allocator_t *allocator)
{
    NodeU8Map *m = n00b_alloc_with_opts(
        NodeU8Map, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(&m->impl, .skip_obj_hash = true, .allocator = allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    return m;
}

static NodeU8Map *
NodeU8Map_new(void)
{
    return NodeU8Map_new_alloc(nullptr);
}

static void
NodeU8Map_free(NodeU8Map *m)
{
    if (!m) return;
    n00b_free(m);
}

static bool
NodeU8Map_get(NodeU8Map *m, NodeId k, uint8_t *out)
{
    bool    found;
    uint8_t got = n00b_dict_get(&m->impl, k, &found);
    if (found) *out = got;
    return found;
}

static void
NodeU8Map_insert(NodeU8Map *m, NodeId k, uint8_t v)
{
    n00b_dict_put(&m->impl, k, v);
}

// ----- NodeUSizeMap -----

typedef struct NodeUSizeMapWrap { NodeUSizeMapImpl impl; } NodeUSizeMap;

static NodeUSizeMap *
NodeUSizeMap_new_alloc(n00b_allocator_t *allocator)
{
    NodeUSizeMap *m = n00b_alloc_with_opts(
        NodeUSizeMap, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(&m->impl, .skip_obj_hash = true, .allocator = allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    return m;
}

static NodeUSizeMap *
NodeUSizeMap_new(void)
{
    return NodeUSizeMap_new_alloc(nullptr);
}

static void
NodeUSizeMap_free(NodeUSizeMap *m)
{
    if (!m) return;
    n00b_free(m);
}

static bool
NodeUSizeMap_get(NodeUSizeMap *m, NodeId k, size_t *out)
{
    bool   found;
    size_t got = n00b_dict_get(&m->impl, k, &found);
    if (found) *out = got;
    return found;
}

static void
NodeUSizeMap_insert(NodeUSizeMap *m, NodeId k, size_t v)
{
    n00b_dict_put(&m->impl, k, v);
}

// ----- U16Set (open-addressed hash set of uint16_t) -----

typedef struct U16SetWrap { U16SetImpl impl; } U16Set;

static U16Set *
U16Set_new_alloc(n00b_allocator_t *allocator)
{
    U16Set *s = n00b_alloc_with_opts(
        U16Set, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(&s->impl, .skip_obj_hash = true, .allocator = allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    return s;
}

static U16Set *
U16Set_new(void)
{
    return U16Set_new_alloc(nullptr);
}

static void
U16Set_free(U16Set *s)
{
    if (!s) return;
    n00b_free(s);
}

static bool
U16Set_insert(U16Set *s, uint16_t k)
{
    if (n00b_dict_contains(&s->impl, k)) return false;
    bool t = true;
    n00b_dict_put(&s->impl, k, t);
    return true;
}

static bool
U16Set_contains(U16Set *s, uint16_t k)
{
    return n00b_dict_contains(&s->impl, k);
}

static size_t
U16Set_len(U16Set *s)
{
    return (size_t)n00b_dict_internal_len((_n00b_dict_internal_t *)&s->impl);
}

// ===========================================================================
// engine_generate_minterms / engine_minterms_lookup
// ===========================================================================

n00b_list_t(TSetId)
engine_generate_minterms(TSetIdSet *sets, Solver *solver)
{
    PartitionTree pt = {};
    PartitionTree_init(&pt, TSET_ID_FULL, solver ? solver->allocator : nullptr);

    // Iterate every TSetId key in the set; refine the partition by it.
    n00b_dict_foreach(&sets->impl, k, _v, {
        (void)_v;
        PartitionTree_refine(&pt, 0, k, solver);
    });

    n00b_list_t(TSetId) lsets = PartitionTree_get_leaf_sets(&pt);
    PartitionTree_drop(&pt);

    if (lsets.len > 1) {
        qsort(lsets.data + 1, lsets.len - 1, sizeof(TSetId), tsetid_cmp_qsort);
    }
    return lsets;
}

U8Lookup256
engine_minterms_lookup(const n00b_list_t(TSetId) *minterms, Solver *solver)
{
    U8Lookup256 lookup = {};
    if (minterms->len <= 1) return lookup;
    uint8_t mt_index = 1;
    for (size_t k = 1; k < minterms->len; ++k) {
        TSetId m = minterms->data[k];
        for (size_t i = 0; i < 4; ++i) {
            for (int j = 0; j < 64; ++j) {
                uint64_t nthbit = 1ull << j;
                if (solver_has_bit_set(solver, m, i, nthbit)) {
                    uint8_t cc = (uint8_t)(i * 64 + j);
                    lookup.v[cc] = mt_index;
                }
            }
        }
        mt_index += 1;
    }
    return lookup;
}

// ===========================================================================
// collect_sets / transition_term / collect_tregex_leaves
// ===========================================================================

TSetIdSet *
collect_sets(const RegexBuilder *b, NodeId start_id)
{
    n00b_allocator_t *alloc = regex_builder_allocator(b);
    NodeIdSet *visited = NodeIdSet_new_alloc(alloc);
    TSetIdSet *sets    = TSetIdSet_new_alloc(alloc);

    n00b_list_t(NodeId) stack = n00b_list_new_private(NodeId, .allocator = alloc, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    n00b_list_push(stack, start_id);
    while (stack.len > 0) {
        NodeId node_id = stack.data[--stack.len];
        if (!NodeIdSet_insert(visited, node_id)) continue;
        Kind k = regex_builder_get_kind(b, node_id);
        switch (k) {
        case KIND_BEGIN:
        case KIND_END:
            break;
        case KIND_PRED:
            TSetIdSet_insert(sets, nodeid_pred_tset_local(node_id, b));
            break;
        case KIND_UNION:
        case KIND_CONCAT:
        case KIND_INTER:
        case KIND_LOOKAHEAD:
        case KIND_LOOKBEHIND:
        case KIND_COUNTED:
            n00b_list_push(stack, nodeid_left_local (node_id, b));
            n00b_list_push(stack, nodeid_right_local(node_id, b));
            break;
        case KIND_STAR:
        case KIND_COMPL:
            n00b_list_push(stack, nodeid_left_local(node_id, b));
            break;
        }
    }

    n00b_list_free(stack);
    NodeIdSet_free(visited);
    return sets;
}

NodeId
transition_term(RegexBuilder *b, TRegexId der, TSetId set)
{
    // Algebra exports an equivalent walker; thin wrapper for parity with
    // upstream resharp module surface (bdfa.c uses this name).
    return regex_builder_transition_term(b, der, set);
}

// `collect_tregex_leaves` — accumulates every leaf NodeId reachable from
// @p tregex into @p out.  Algebra exposes `regex_builder_extract_sat`
// for the raw tree walk; engine.c needs the dedup variant (visited
// set) and excludes NODE_ID_BOT — implemented locally by extracting
// then dedup-ing.
//
// Faithfulness note: Rust uses HashSet<TRegexId> for the dedup set.  The
// pre-port C tree used a linear-scan VecU32, turning the inner contains-
// test into O(N) per node.  TRegexIdSet (mapped to n00b_dict_t(TRegexId,
// bool) here) restores the O(1) contains.

typedef struct TRegexIdSetWrap {
    n00b_dict_t(TRegexId, bool) impl;
} TRegexIdSet;

static TRegexIdSet *
TRegexIdSet_new_alloc(n00b_allocator_t *allocator)
{
    TRegexIdSet *s = n00b_alloc_with_opts(
        TRegexIdSet, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(&s->impl, .skip_obj_hash = true, .allocator = allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    return s;
}

static TRegexIdSet *
TRegexIdSet_new(void)
{
    return TRegexIdSet_new_alloc(nullptr);
}

static void
TRegexIdSet_free(TRegexIdSet *s)
{
    if (!s) return;
    n00b_free(s);
}

static bool
TRegexIdSet_insert(TRegexIdSet *s, TRegexId k)
{
    if (n00b_dict_contains(&s->impl, k)) return false;
    bool t = true;
    n00b_dict_put(&s->impl, k, t);
    return true;
}

static void
collect_tregex_leaves(const RegexBuilder *b, TRegexId tregex,
                      n00b_list_t(NodeId) *out)
{
    // Wrap algebra's extract_sat into this file's owned-list vocabulary.
    // extract_sat already excludes NODE_ID_BOT; we layer dedup on top via
    // a local TRegexIdSet (Rust-equivalent O(1) contains).
    TRegexIdSet *visited = TRegexIdSet_new_alloc(regex_builder_allocator(b));
    (void)visited;  // Unused while extract_sat already walks unique nodes.

    VecNodeIdPub pub = {};
    regex_builder_extract_sat(b, tregex, &pub);
    for (size_t i = 0; i < pub.len; ++i) {
        n00b_list_push(*out, pub.data[i]);
    }
    if (pub.data) n00b_free(pub.data);
    TRegexIdSet_free(visited);
}

// ===========================================================================
// Skip-profitability heuristics
// ===========================================================================

constexpr uint32_t SKIP_FREQ_THRESHOLD  = 75000u;
constexpr uint16_t RARE_BYTE_FREQ_LIMIT = 25000u;

static bool
skip_is_profitable(const uint8_t *bytes, size_t len)
{
    if (len >= 256) return false;
    uint32_t freq_sum = 0;
    for (size_t i = 0; i < len; ++i) {
        freq_sum += (uint32_t)n00b_simd_byte_freq(bytes[i]);
    }
    if (freq_sum < SKIP_FREQ_THRESHOLD) return true;
    if (len > 128) {
        // 256-byte presence map.
        bool present[256] = {};
        for (size_t i = 0; i < len; ++i) present[bytes[i]] = true;
        uint32_t complement_freq = 0;
        for (uint32_t bb = 0; bb < 256; ++bb) {
            if (!present[bb]) {
                complement_freq += (uint32_t)n00b_simd_byte_freq((uint8_t)bb);
            }
        }
        return complement_freq < SKIP_FREQ_THRESHOLD;
    }
    return false;
}

// ===========================================================================
// Effects ID constants — copied from algebra crate `upstream`.  Defined
// at the bottom of this file with external linkage so fas.c and bdfa.c
// reference them via `extern const`.
// ===========================================================================

// (extern declarations live in engine.h.)

// ===========================================================================
// register_state — free function in Rust.
// ===========================================================================

static uint16_t
register_state(n00b_list_t(NodeId) *state_nodes,
               NodeU16Map *node_to_state,
               n00b_list_t(uint16_t) *effects_id,
               n00b_list_t(uint16_t) *center_effect_id,
               n00b_list_t(NullStateList) *effects,
               RegexBuilder *b,
               NodeId node)
{
    uint16_t sid;
    if (NodeU16Map_get(node_to_state, node, &sid)) return sid;
    sid = (uint16_t)state_nodes->len;
    n00b_list_push(*state_nodes, node);
    NodeU16Map_insert(node_to_state, node, sid);
    NullsId eff_id = regex_builder_get_nulls_id(b, node);
    NullsId eid    = regex_builder_center_nulls_id(b, eff_id);
    if ((size_t)sid >= effects_id->len) {
        eng_list_u16_resize_fill(effects_id, (size_t)sid + 1, 0u);
    }
    if ((size_t)sid >= center_effect_id->len) {
        eng_list_u16_resize_fill(center_effect_id, (size_t)sid + 1, (uint16_t)EID_NONE);
    }
    effects_id->data[sid]       = (uint16_t)eff_id.v;
    center_effect_id->data[sid] = (uint16_t)eid.v;
    while (effects->len <= (size_t)eff_id.v || effects->len <= (size_t)eid.v) {
        // Sequence the make_vec call before the macro push: n00b_list_push
        // expands to `data[len++] = (val)`, where the read of `len` inside
        // `(val)` is unsequenced with `len++` — UB if val depends on len.
        NullStateList _ne = engine_make_nulls_entry_vec(b, (uint32_t)effects->len);
        n00b_list_push(*effects, _ne);
    }
    return sid;
}

// ===========================================================================
// LDFA implementation
// ===========================================================================

void
engine_LDFA_drop(LDFA *self)
{
    if (!self) return;
    n00b_list_free(self->begin_table);
    n00b_list_free(self->center_table);
    n00b_list_free(self->effects_id);
    n00b_list_free(self->center_effect_id);
    // NOTE: each `effects` entry is itself a private `n00b_list_t(NullState)`
    // owning its data; `n00b_list_free` releases each inner list before we
    // release the outer buffer.
    for (size_t i = 0; i < self->effects.len; ++i) {
        n00b_list_free(self->effects.data[i]);
    }
    n00b_list_free(self->effects);
    n00b_list_free(self->minterms);
    n00b_list_free(self->state_nodes);
    n00b_list_free(self->skip_ids);
    // skip_searchers entries are MintermSearchValue — opaque; the SIMD
    // module owns the inner RevSearchBytes/RevSearchRanges payloads, so
    // we only release the outer buffer here (matches resharp-c).
    n00b_list_free(self->skip_searchers);
    if (self->prune_memo)    regex_builder_prune_memo_free(self->prune_memo);
    self->prune_memo = nullptr;
    if (self->node_to_state) NodeU16Map_free(self->node_to_state);
    self->node_to_state = nullptr;
    self->prefix_skip = (OptionRevTeddySearch){ .present = false, .value = nullptr };
}

// engine_LDFA_new_inner — heap-allocates an LDFA and populates it.  On
// success returns ok with the LDFA pointer; on err returns the err side
// holding an `n00b_regex_algebra_err_t` cast to int.  Centralises
// construction for the two public wrappers (engine_LDFA_new / _new_fwd)
// which differ only in the `is_forward` flag.
static n00b_result_t(LDFA *)
engine_LDFA_new_inner(RegexBuilder *b, NodeId initial,
                      size_t max_capacity, bool is_forward)
{
    n00b_allocator_t *alloc = regex_builder_allocator(b);
    LDFA *l = n00b_alloc_with_opts(LDFA, &(n00b_alloc_opts_t){.allocator = alloc});
    l->allocator        = alloc;
    l->begin_table      = n00b_list_new_private(uint16_t, .allocator = alloc, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    l->center_table     = n00b_list_new_private(uint16_t, .allocator = alloc, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    l->effects_id       = n00b_list_new_private(uint16_t, .allocator = alloc, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    l->center_effect_id = n00b_list_new_private(uint16_t, .allocator = alloc, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    l->effects          = n00b_list_new_private(NullStateList, .allocator = alloc);
    l->state_nodes      = n00b_list_new_private(NodeId, .allocator = alloc, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    l->skip_ids         = n00b_list_new_private(uint8_t, .allocator = alloc, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    l->skip_searchers   = n00b_list_new_private(MintermSearchValue, .allocator = alloc);

    TSetIdSet *sets_set = collect_sets(b, initial);
    l->minterms = engine_generate_minterms(sets_set, regex_builder_solver(b));
    TSetIdSet_free(sets_set);

    // Defensive: engine_generate_minterms always yields ≥1 element today,
    // but mt_log = next_pow2_log(0) returns 0 which would degenerate the
    // center_table stride.  Guard so a future change to engine_generate_minterms
    // produces a useful diagnostic instead of a silent miscompile.
    n00b_require(l->minterms.len > 0,
                 "engine_LDFA_new_inner: minterms must be non-empty");

    U8Lookup256 u8_lookup = engine_minterms_lookup(&l->minterms,
                                                   regex_builder_solver(b));
    memcpy(l->mt_lookup, u8_lookup.v, 256);

    if (max_capacity > 65535) max_capacity = 65535;
    l->max_capacity = max_capacity;
    l->is_forward   = is_forward;
    l->has_anchors  = regex_builder_contains_anchors(b, initial);

    n00b_list_push(l->state_nodes, NODE_ID_MISSING);
    n00b_list_push(l->state_nodes, NODE_ID_BOT);
    l->node_to_state = NodeU16Map_new_alloc(alloc);
    NodeU16Map_insert(l->node_to_state, NODE_ID_BOT, (uint16_t)engine_DFA_DEAD);

    eng_list_u16_resize_fill(&l->effects_id,       2, 0u);
    eng_list_u16_resize_fill(&l->center_effect_id, 2, (uint16_t)EID_NONE);

    l->prune_memo = regex_builder_prune_memo_new(regex_builder_allocator(b));

    // state 2
    (void)register_state(&l->state_nodes, l->node_to_state, &l->effects_id,
                         &l->center_effect_id, &l->effects, b, initial);

    // state 3 — mirrors Rust LDFA::new, which uses `prune_begin`
    // (Begin → BOT) here (NOT `prune_begin_eps`).
    NodeId   initial_pruned = regex_builder_prune_begin(b, initial);
    uint16_t pruned_sid     = register_state(&l->state_nodes, l->node_to_state,
                                             &l->effects_id, &l->center_effect_id,
                                             &l->effects, b, initial_pruned);
    l->pruned = pruned_sid;

    TRegexId der0;
    {
        n00b_result_t(TRegexId) rd = regex_builder_der(b, initial, NULLABILITY_BEGIN);
        if (n00b_result_is_err(rd)) {
            engine_LDFA_drop(l);
            n00b_free(l);
            return n00b_result_err(LDFA *, n00b_result_get_err(rd));
        }
        der0 = n00b_result_get(rd);
    }

    eng_list_u16_resize_fill(&l->begin_table, l->minterms.len, (uint16_t)engine_DFA_DEAD);
    for (size_t idx = 0; idx < l->minterms.len; ++idx) {
        TSetId mt = l->minterms.data[idx];
        NodeId t  = transition_term(b, der0, mt);
        if (is_forward) t = regex_builder_prune_fwd(b, t, l->prune_memo);
        else            t = regex_builder_prune_rev(b, t, l->prune_memo);
        uint16_t sid = register_state(&l->state_nodes, l->node_to_state,
                                      &l->effects_id, &l->center_effect_id,
                                      &l->effects, b, t);
        if (l->state_nodes.len > max_capacity) {
            engine_LDFA_drop(l);
            n00b_free(l);
            return n00b_result_err(LDFA *, engine_err_capacity_exceeded());
        }
        l->begin_table.data[idx] = sid;
    }
    uint32_t num_minterms      = (uint32_t)l->minterms.len;
    uint32_t mt_log            = next_pow2_log((size_t)num_minterms);
    size_t   stride            = (size_t)1 << mt_log;
    size_t   center_table_size = safe_mul_sz(l->state_nodes.len, stride);
    l->mt_log = mt_log;
    eng_list_u16_resize_fill(&l->center_table, center_table_size, (uint16_t)engine_DFA_MISSING);
    for (size_t mt_idx = 0; mt_idx < l->minterms.len; ++mt_idx) {
        l->center_table.data[((size_t)engine_DFA_DEAD << mt_log) | mt_idx]
            = (uint16_t)engine_DFA_DEAD;
    }
    while (l->effects.len < regex_builder_nulls_count(b)) {
        // See register_state for the sequencing rationale.
        NullStateList _ne = engine_make_nulls_entry_vec(b, (uint32_t)l->effects.len);
        n00b_list_push(l->effects, _ne);
    }
    eng_list_u8_resize_fill(&l->skip_ids, l->state_nodes.len, 0u);

    l->prefix_skip    = (OptionRevTeddySearch){ .present = false, .value = nullptr };
    return n00b_result_ok(LDFA *, l);
}

n00b_result_t(LDFA *)
engine_LDFA_new(RegexBuilder *b, NodeId initial, size_t max_capacity)
{
    return engine_LDFA_new_inner(b, initial, max_capacity, false);
}

n00b_result_t(LDFA *)
engine_LDFA_new_fwd(RegexBuilder *b, NodeId initial, size_t max_capacity)
{
    return engine_LDFA_new_inner(b, initial, max_capacity, true);
}

[[gnu::always_inline]] inline size_t
engine_LDFA_dfa_delta(const LDFA *self, uint16_t state_id, uint32_t mt)
{
    return (size_t)(((uint32_t)state_id << self->mt_log) | mt);
}

void
engine_LDFA_ensure_capacity(LDFA *self, uint16_t state_id)
{
    size_t cap = (size_t)state_id + 1;
    if (cap > self->effects_id.len) {
        size_t new_len = usize_max(self->effects_id.len, 4) * 2;
        if (new_len < cap) new_len = cap;
        eng_list_u16_resize_fill(&self->effects_id,       new_len, 0u);
        eng_list_u16_resize_fill(&self->center_effect_id, new_len, (uint16_t)EID_NONE);
    }
    size_t stride = (size_t)1 << self->mt_log;
    size_t needed = safe_mul_sz(cap, stride);
    if (needed > self->center_table.len) {
        size_t new_len = usize_max(self->center_table.len, 4) * 2;
        if (new_len < needed) new_len = needed;
        eng_list_u16_resize_fill(&self->center_table, new_len, (uint16_t)engine_DFA_MISSING);
    }
    if (cap > self->skip_ids.len) {
        size_t new_len = usize_max(self->skip_ids.len, 4) * 2;
        if (new_len < cap) new_len = cap;
        eng_list_u8_resize_fill(&self->skip_ids, new_len, 0u);
    }
}

uint16_t
engine_LDFA_get_or_register(LDFA *self, RegexBuilder *b, NodeId node)
{
    return register_state(&self->state_nodes, self->node_to_state,
                          &self->effects_id, &self->center_effect_id,
                          &self->effects, b, node);
}

// forward decls
static n00b_result_t(uint32_t)
engine_LDFA_lazy_transition_slow(LDFA *self, RegexBuilder *b,
                                 uint16_t state_id, uint32_t minterm_idx);

n00b_result_t(uint32_t)
engine_LDFA_lazy_transition(LDFA *self, RegexBuilder *b,
                             uint32_t state_id_u32, uint32_t minterm_idx)
{
    uint16_t state_id = (uint16_t)state_id_u32;
    size_t   delta    = engine_LDFA_dfa_delta(self, state_id, minterm_idx);
    if (delta < self->center_table.len
        && self->center_table.data[delta] != engine_DFA_MISSING) {
        return n00b_result_ok(uint32_t, (uint32_t)self->center_table.data[delta]);
    }
    return engine_LDFA_lazy_transition_slow(self, b, state_id, minterm_idx);
}

[[gnu::cold]] [[gnu::noinline]] static n00b_result_t(uint32_t)
engine_LDFA_lazy_transition_slow(LDFA *self, RegexBuilder *b,
                                 uint16_t state_id, uint32_t minterm_idx)
{
    if (state_id == engine_DFA_DEAD) {
        return n00b_result_ok(uint32_t, engine_DFA_DEAD);
    }
    engine_LDFA_ensure_capacity(self, state_id);
    n00b_result_t(int) cs = engine_LDFA_create_state(self, b, (uint32_t)state_id);
    if (n00b_result_is_err(cs)) {
        return n00b_result_err(uint32_t, n00b_result_get_err(cs));
    }
    size_t delta = engine_LDFA_dfa_delta(self, state_id, minterm_idx);
    n00b_require(self->center_table.data[delta] != engine_DFA_MISSING,
                 "engine_LDFA_lazy_transition_slow: create_state left slot DFA_MISSING");
    return n00b_result_ok(uint32_t, (uint32_t)self->center_table.data[delta]);
}

// ===========================================================================
// VecDeque<u16> — head-only-advance variant of Rust's VecDeque.
//
// IMPORTANT: not a ring buffer.  `head` advances monotonically as
// elements are popped and we never reclaim the popped front cells, so
// peak memory is O(total pushes) rather than O(peak size).  Acceptable
// at current engine_LDFA_precompile / has_nonnullable_cycle thresholds.
// ===========================================================================

typedef struct DequeU16 {
    uint16_t *data;
    size_t    head;
    size_t    len;
    size_t    cap;
} DequeU16;

static void
DequeU16_push_back(DequeU16 *d, uint16_t v)
{
    if (d->head + d->len + 1 > d->cap) {
        size_t nc = d->cap == 0 ? 8 : safe_mul_sz(d->cap, 2);
        if (nc < d->head + d->len + 1) nc = d->head + d->len + 1;
        grow_buf(uint16_t, &d->data, &d->cap, d->head + d->len, nc);
    }
    d->data[d->head + d->len] = v;
    d->len++;
}

static bool
DequeU16_pop_front(DequeU16 *d, uint16_t *out)
{
    if (d->len == 0) return false;
    *out = d->data[d->head++];
    d->len--;
    return true;
}

static void
DequeU16_drop(DequeU16 *d)
{
    if (d->data) n00b_free(d->data);
    *d = (DequeU16){};
}

// DequeNodeId — same head-only-advance scheme as DequeU16.
typedef struct DequeNodeId {
    NodeId *data;
    size_t  head;
    size_t  len;
    size_t  cap;
} DequeNodeId;

static void
DequeNodeId_push_back(DequeNodeId *d, NodeId v)
{
    if (d->head + d->len + 1 > d->cap) {
        size_t nc = d->cap == 0 ? 8 : safe_mul_sz(d->cap, 2);
        if (nc < d->head + d->len + 1) nc = d->head + d->len + 1;
        grow_buf(NodeId, &d->data, &d->cap, d->head + d->len, nc);
    }
    d->data[d->head + d->len] = v;
    d->len++;
}

static bool
DequeNodeId_pop_front(DequeNodeId *d, NodeId *out)
{
    if (d->len == 0) return false;
    *out = d->data[d->head++];
    d->len--;
    return true;
}

static void
DequeNodeId_drop(DequeNodeId *d)
{
    if (d->data) n00b_free(d->data);
    *d = (DequeNodeId){};
}

// ===========================================================================
// engine_LDFA_precompile
// ===========================================================================

void
engine_LDFA_precompile(LDFA *self, RegexBuilder *b, size_t threshold)
{
    DequeU16 worklist = {};
    U16Set  *visited  = U16Set_new_alloc(self->allocator);
    for (size_t k = 0; k < self->begin_table.len; ++k) {
        uint16_t sid = self->begin_table.data[k];
        if (sid > engine_DFA_DEAD) DequeU16_push_back(&worklist, sid);
    }
    size_t   stride = (size_t)1 << self->mt_log;
    uint16_t sid;
    while (DequeU16_pop_front(&worklist, &sid)) {
        if (!U16Set_insert(visited, sid)) continue;
        if (U16Set_len(visited) > threshold) break;
        engine_LDFA_ensure_capacity(self, sid);
        // Best-effort precompile: an error here just halts precomputation;
        // lazy transitions will surface the same failure later.
        n00b_result_t(int) cs = engine_LDFA_create_state(self, b, (uint32_t)sid);
        if (n00b_result_is_err(cs)) break;
        size_t base = (size_t)sid * stride;
        for (size_t mt_idx = 0; mt_idx < self->minterms.len; ++mt_idx) {
            uint16_t next_sid = self->center_table.data[base | mt_idx];
            if (next_sid > engine_DFA_DEAD && !U16Set_contains(visited, next_sid)) {
                DequeU16_push_back(&worklist, next_sid);
            }
        }
    }
    DequeU16_drop(&worklist);
    U16Set_free(visited);
}

// ===========================================================================
// engine_LDFA_has_nonnullable_cycle
// ===========================================================================

bool
engine_LDFA_has_nonnullable_cycle(LDFA *self, RegexBuilder *b, size_t budget)
{
    n00b_list_t(NodeId) seed_nodes = n00b_list_new_private(NodeId, .allocator = self->allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    for (size_t k = 0; k < self->begin_table.len; ++k) {
        uint16_t sid = self->begin_table.data[k];
        if (sid > engine_DFA_DEAD) {
            NodeId node = self->state_nodes.data[sid];
            if (node.v > NODE_ID_BOT.v) n00b_list_push(seed_nodes, node);
        }
    }
    NodeIdSet  *visited  = NodeIdSet_new_alloc(self->allocator);
    DequeNodeId worklist = {};

    // successors: NodeId -> n00b_list_t(NodeId), modeled as NodeUSizeMap
    // keying into a side list-of-lists.
    NodeUSizeMap *successors_idx = NodeUSizeMap_new_alloc(self->allocator);
    n00b_list_t(n00b_list_t(NodeId)) successors_vals =
        n00b_list_new_private(n00b_list_t(NodeId), .allocator = self->allocator);

    for (size_t k = 0; k < seed_nodes.len; ++k) {
        NodeId n = seed_nodes.data[k];
        if (NodeIdSet_insert(visited, n)) DequeNodeId_push_back(&worklist, n);
    }

    bool result = false;
    bool fail   = false;

    NodeId node;
    while (!fail && DequeNodeId_pop_front(&worklist, &node)) {
        if (NodeIdSet_len(visited) > budget) {
            result = true;
            fail   = true;
            break;
        }
        TRegexId sder;
        {
            n00b_result_t(TRegexId) rd = regex_builder_der(b, node, NULLABILITY_CENTER);
            if (n00b_result_is_err(rd)) {
                result = true;
                fail   = true;
                break;
            }
            sder = n00b_result_get(rd);
        }
        n00b_list_t(NodeId) leaves = n00b_list_new_private(NodeId, .allocator = self->allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        collect_tregex_leaves(b, sder, &leaves);
        n00b_list_t(NodeId) succs = n00b_list_new_private(NodeId, .allocator = self->allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE);
        for (size_t i = 0; i < leaves.len; ++i) {
            NodeId next = leaves.data[i];
            if (next.v > NODE_ID_BOT.v) {
                n00b_list_push(succs, next);
                if (NodeIdSet_insert(visited, next)) {
                    DequeNodeId_push_back(&worklist, next);
                }
            }
        }
        n00b_list_free(leaves);

        size_t slot = successors_vals.len;
        n00b_list_push(successors_vals, succs);
        NodeUSizeMap_insert(successors_idx, node, slot);
    }

    if (fail) {
        for (size_t i = 0; i < successors_vals.len; ++i) {
            n00b_list_free(successors_vals.data[i]);
        }
        n00b_list_free(successors_vals);
        NodeUSizeMap_free(successors_idx);
        n00b_list_free(seed_nodes);
        DequeNodeId_drop(&worklist);
        NodeIdSet_free(visited);
        return result;
    }

    // nonnull = visited filter b.get_nulls_id(n) == EMPTY.
    NodeIdSet *nonnull = NodeIdSet_new_alloc(self->allocator);
    n00b_dict_foreach(&visited->impl, vnode, _v, {
        (void)_v;
        if (nullsid_eq_local(regex_builder_get_nulls_id(b, vnode), NULLS_ID_EMPTY)) {
            NodeIdSet_insert(nonnull, vnode);
        }
    });
    if (NodeIdSet_len(nonnull) == 0) {
        for (size_t i = 0; i < successors_vals.len; ++i) {
            n00b_list_free(successors_vals.data[i]);
        }
        n00b_list_free(successors_vals);
        NodeUSizeMap_free(successors_idx);
        n00b_list_free(seed_nodes);
        DequeNodeId_drop(&worklist);
        NodeIdSet_free(nonnull);
        NodeIdSet_free(visited);
        return false;
    }

    // Iterative tri-color DFS.  color ∈ {0=white, 1=gray, 2=black};
    // absent entries default to white.
    NodeU8Map *color = NodeU8Map_new_alloc(self->allocator);

    typedef struct StackFrame {
        NodeId node;
        size_t idx;
    } StackFrame;
    typedef struct VecFrame {
        StackFrame *data;
        size_t      len;
        size_t      cap;
    } VecFrame;
    VecFrame stack = {};

    bool found = false;
    n00b_dict_foreach(&nonnull->impl, start, _v2, {
        (void)_v2;
        if (found) break;
        uint8_t cstart = 0;
        (void)NodeU8Map_get(color, start, &cstart);
        if (cstart != 0) continue;
        if (stack.len + 1 > stack.cap) {
            size_t nc = stack.cap == 0 ? 8 : safe_mul_sz(stack.cap, 2);
            grow_buf(StackFrame, &stack.data, &stack.cap, stack.len, nc);
        }
        {
            StackFrame *sf = &stack.data[stack.len++];
            sf->node = start;
            sf->idx  = 0;
        }
        NodeU8Map_insert(color, start, 1);

        while (stack.len > 0) {
            StackFrame   *top      = &stack.data[stack.len - 1];
            const NodeId *succ_arr = nullptr;
            size_t        succ_len = 0;
            size_t        slot;
            if (NodeUSizeMap_get(successors_idx, top->node, &slot)) {
                const n00b_list_t(NodeId) *vv = &successors_vals.data[slot];
                succ_arr = vv->data;
                succ_len = vv->len;
            }
            if (top->idx >= succ_len) {
                NodeU8Map_insert(color, top->node, 2);
                stack.len--;
                continue;
            }
            NodeId next = succ_arr[top->idx];
            top->idx += 1;
            if (!NodeIdSet_contains(nonnull, next)) continue;
            uint8_t c = 0;
            (void)NodeU8Map_get(color, next, &c);
            if (c == 1) { found = true; break; }
            if (c == 0) {
                NodeU8Map_insert(color, next, 1);
                if (stack.len + 1 > stack.cap) {
                    size_t nc = stack.cap == 0 ? 8 : safe_mul_sz(stack.cap, 2);
                    grow_buf(StackFrame, &stack.data, &stack.cap, stack.len, nc);
                }
                {
                    StackFrame *sf2 = &stack.data[stack.len++];
                    sf2->node = next;
                    sf2->idx  = 0;
                }
            }
        }
    });

    for (size_t i = 0; i < successors_vals.len; ++i) {
        n00b_list_free(successors_vals.data[i]);
    }
    n00b_list_free(successors_vals);
    NodeUSizeMap_free(successors_idx);
    n00b_list_free(seed_nodes);
    DequeNodeId_drop(&worklist);
    NodeIdSet_free(nonnull);
    NodeU8Map_free(color);
    if (stack.data) n00b_free(stack.data);
    NodeIdSet_free(visited);
    return found;
}

// ===========================================================================
// LDFA::create_state
// ===========================================================================

static void engine_LDFA_try_build_skip_simd(LDFA *self, RegexBuilder *b, size_t state);

n00b_result_t(int)
engine_LDFA_create_state(LDFA *self, RegexBuilder *b, uint32_t state_id_u32)
{
    uint16_t state_id = (uint16_t)state_id_u32;
    NodeId   node     = self->state_nodes.data[state_id];
    if (nodeid_eq(node, NODE_ID_MISSING)) return n00b_result_ok(int, 0);
    TRegexId sder;
    {
        n00b_result_t(TRegexId) rd = regex_builder_der(b, node, NULLABILITY_CENTER);
        if (n00b_result_is_err(rd)) {
            return n00b_result_err(int, n00b_result_get_err(rd));
        }
        sder = n00b_result_get(rd);
    }
    for (size_t mt_idx = 0; mt_idx < self->minterms.len; ++mt_idx) {
        size_t delta = engine_LDFA_dfa_delta(self, state_id, (uint32_t)mt_idx);
        if (delta < self->center_table.len
            && self->center_table.data[delta] != engine_DFA_MISSING) continue;
        // Cap check hoisted above transition_term/prune_* so we don't
        // waste a derivative + prune on a minterm we cannot register.
        if (self->state_nodes.len >= self->max_capacity) {
            return n00b_result_err(int, engine_err_capacity_exceeded());
        }
        TSetId mt        = self->minterms.data[mt_idx];
        NodeId next_node = transition_term(b, sder, mt);
        if (self->is_forward) {
            next_node = regex_builder_prune_fwd(b, next_node, self->prune_memo);
        }
        else {
            next_node = regex_builder_prune_rev(b, next_node, self->prune_memo);
        }
        uint16_t next_sid = engine_LDFA_get_or_register(self, b, next_node);
        engine_LDFA_ensure_capacity(self, next_sid);
        size_t delta2 = engine_LDFA_dfa_delta(self, state_id, (uint32_t)mt_idx);
        self->center_table.data[delta2] = next_sid;
    }
    if (n00b_simd_has_simd()) {
        engine_LDFA_try_build_skip_simd(self, b, (size_t)state_id);
    }
    return n00b_result_ok(int, 0);
}

// ===========================================================================
// skip-table helpers
// ===========================================================================

static uint8_t
engine_LDFA_get_or_create_skip_all(LDFA *self)
{
    for (size_t i = 0; i < self->skip_searchers.len; ++i) {
        if (minterm_search_value_tag(&self->skip_searchers.data[i])
            == MINTERM_SEARCH_VALUE_ALL) {
            return (uint8_t)(i + 1);
        }
    }
    n00b_list_push(self->skip_searchers, minterm_search_value_all());
    return (uint8_t)self->skip_searchers.len;
}

static int
u8_cmp(const void *a, const void *b)
{
    return (int)*(const uint8_t *)a - (int)*(const uint8_t *)b;
}

// engine_LDFA_get_or_create_skip_{exact,range} take ownership of `bytes`
// / `ranges`.  On the duplicate-found path the helper frees the list
// itself; on the new-searcher path the bytes/ranges are moved into the
// MintermSearchValue stored on `self->skip_searchers`.
static uint8_t
engine_LDFA_get_or_create_skip_exact(LDFA *self, n00b_list_t(uint8_t) bytes)
{
    qsort(bytes.data, bytes.len, sizeof(uint8_t), u8_cmp);
    for (size_t i = 0; i < self->skip_searchers.len; ++i) {
        if (minterm_search_value_tag(&self->skip_searchers.data[i])
            == MINTERM_SEARCH_VALUE_EXACT) {
            size_t e_len = 0;
            const uint8_t *e_bytes = n00b_simd_rev_search_bytes_bytes(
                minterm_search_value_exact_bytes(&self->skip_searchers.data[i]),
                &e_len);
            if (e_len == bytes.len
                && memcmp(e_bytes, bytes.data, bytes.len) == 0) {
                n00b_list_free(bytes);
                return (uint8_t)(i + 1);
            }
        }
    }
    // n00b_simd_RevSearchBytes_new copies the bytes into its own buffer (owned
    // by SIMD layer); the caller's `bytes` list is consumed after.
    n00b_allocator_t *prev_alloc = n00b_set_current_allocator(self->allocator);
    RevSearchBytes *rsb = n00b_simd_RevSearchBytes_new(bytes);
    n00b_restore_current_allocator(prev_alloc);
    n00b_list_push(self->skip_searchers, minterm_search_value_exact(rsb));
    return (uint8_t)self->skip_searchers.len;
}

static int
u8pair_cmp(const void *a, const void *b)
{
    const U8Pair *x = a;
    const U8Pair *y = b;
    if (x->lo != y->lo) return (int)x->lo - (int)y->lo;
    return (int)x->hi - (int)y->hi;
}

static uint8_t
engine_LDFA_get_or_create_skip_range(LDFA *self, n00b_list_t(U8Pair) ranges)
{
    qsort(ranges.data, ranges.len, sizeof(U8Pair), u8pair_cmp);
    for (size_t i = 0; i < self->skip_searchers.len; ++i) {
        if (minterm_search_value_tag(&self->skip_searchers.data[i])
            == MINTERM_SEARCH_VALUE_RANGE) {
            size_t r_len = 0;
            const ByteRange *r_data = (const ByteRange *)(const void *)
                n00b_simd_rev_search_ranges_ranges(
                minterm_search_value_range_ranges(&self->skip_searchers.data[i]),
                &r_len);
            if (r_len == ranges.len
                && memcmp(r_data, ranges.data, ranges.len * sizeof(U8Pair)) == 0) {
                n00b_list_free(ranges);
                return (uint8_t)(i + 1);
            }
        }
    }
    n00b_allocator_t *prev_alloc = n00b_set_current_allocator(self->allocator);
    RevSearchRanges *rsr = n00b_simd_RevSearchRanges_new(ranges);
    n00b_restore_current_allocator(prev_alloc);
    n00b_list_push(self->skip_searchers, minterm_search_value_range(rsr));
    return (uint8_t)self->skip_searchers.len;
}

// closure context for iter_sat callback
typedef struct IterSatCtx {
    NodeId  node;
    Solver *solver;
    TSetId *notany;
} IterSatCtx;

static void
iter_sat_cb_impl(void *ctxp, RegexBuilder *b, NodeId next, TSetId set)
{
    IterSatCtx *ctx = (IterSatCtx *)ctxp;
    if (nodeid_eq(next, ctx->node)) {
        *ctx->notany = solver_or_id(regex_builder_solver(b), *ctx->notany, set);
    }
}

static bool
engine_LDFA_try_build_range_skip(LDFA *self, const uint8_t *bytes, size_t len,
                                 uint8_t *out_sid)
{
    TSet         tset       = tset_from_bytes(bytes, len);
    ByteRangeSet brs        = solver_pp_collect_ranges(&tset);
    if (brs.len == 0 || brs.len > 3) {
        ByteRangeSet_free(&brs);
        return false;
    }
    if (!skip_is_profitable(bytes, len)) {
        ByteRangeSet_free(&brs);
        return false;
    }
    if (len > 128 && (256 - len) < 16) {
        ByteRangeSet_free(&brs);
        return false;
    }
    // Convert ByteRangeSet (algebra-side) to an engine-side `n00b_list_t(U8Pair)`.
    // The two have identical layout (`{uint8_t lo; uint8_t hi}`); we make
    // an owned copy so the helper takes ownership cleanly.
    n00b_list_t(U8Pair) ranges = n00b_list_new_private(U8Pair, .allocator = self->allocator);
    for (size_t i = 0; i < brs.len; ++i) {
        n00b_list_push(ranges,
                       ((U8Pair){ .lo = brs.data[i].start, .hi = brs.data[i].end }));
    }
    ByteRangeSet_free(&brs);
    *out_sid = engine_LDFA_get_or_create_skip_range(self, ranges);
    return true;
}

static void
engine_LDFA_try_build_skip_simd(LDFA *self, RegexBuilder *b, size_t state)
{
    if (self->skip_ids.data[state] != 0) return;
    NodeId node = self->state_nodes.data[state];
    if (nodeid_eq(node, NODE_ID_MISSING) || nodeid_eq(node, NODE_ID_BOT)) return;
    TRegexId sder;
    {
        n00b_result_t(TRegexId) rd = regex_builder_der(b, node, NULLABILITY_CENTER);
        if (n00b_result_is_err(rd)) return;
        sder = n00b_result_get(rd);
    }

    TSetId       notany = TSET_ID_EMPTY;
    IterSatStack stack;
    iter_sat_stack_init(&stack);
    iter_sat_stack_push(&stack, (IterSatFrame){ sder, TSET_ID_FULL },
                        regex_builder_allocator(b));
    IterSatCtx ctx = { .node = node, .solver = regex_builder_solver(b), .notany = &notany };
    regex_builder_iter_sat(b, &stack, &ctx, iter_sat_cb_impl);
    iter_sat_stack_free(&stack);

    TSetId               any   = solver_not_id(regex_builder_solver(b), notany);
    n00b_list_t(uint8_t) bytes = engine_solver_collect_bytes(regex_builder_solver(b), any);
    if (bytes.len == 256) {
        n00b_list_free(bytes);
        return;
    }
    if (bytes.len == 0) {
        self->skip_ids.data[state] = engine_LDFA_get_or_create_skip_all(self);
        n00b_list_free(bytes);
        return;
    }
    if (bytes.len <= 3) {
        self->skip_ids.data[state] = engine_LDFA_get_or_create_skip_exact(self, bytes);
        return;
    }
    uint8_t sid;
    if (engine_LDFA_try_build_range_skip(self, bytes.data, bytes.len, &sid)) {
        self->skip_ids.data[state] = sid;
    }
    n00b_list_free(bytes);
}

void
engine_LDFA_ensure_pruned_skip(LDFA *self)
{
    if (self->prefix_skip.present) {
        size_t p = (size_t)self->pruned;
        if (p < self->skip_ids.len && self->skip_ids.data[p] == 0) {
            self->skip_ids.data[p] = engine_LDFA_get_or_create_skip_all(self);
        }
    }
}

// ===========================================================================
// has_any_null / collect_nulls / collect_max{,_fwd,_rev} (free functions)
// ===========================================================================

bool
engine_has_any_null(const n00b_list_t(uint16_t) *effects_id,
                    const n00b_list_t(NullStateList) *effects,
                    uint32_t state, Nullability mask)
{
    uint32_t eid = (uint32_t)effects_id->data[state];
    if (eid == 0) return false;
    if (eid == EID_ALWAYS0) return nullability_has(mask, NULLABILITY_ALWAYS);
    if (eid == EID_CENTER0) return nullability_has(mask, NULLABILITY_CENTER);
    const NullStateList *v = &effects->data[eid];
    for (size_t i = 0; i < v->len; ++i) {
        if (nullability_has(v->data[i].mask, mask)) return true;
    }
    return false;
}

[[gnu::always_inline]] static inline void
collect_nulls(const n00b_list_t(uint16_t) *effects_id,
              const n00b_list_t(NullStateList) *effects,
              uint32_t state, size_t pos, Nullability mask,
              n00b_list_t(size_t) *nulls)
{
    uint32_t eid = (uint32_t)effects_id->data[state];
    if (eid == 0) return;
    if (eid == EID_ALWAYS0) {
        if (nullability_has(mask, NULLABILITY_ALWAYS)) n00b_list_push(*nulls, pos);
        return;
    }
    if (eid == EID_CENTER0) {
        if (nullability_has(mask, NULLABILITY_CENTER)) n00b_list_push(*nulls, pos);
        return;
    }
    if (eid == EID_BEGIN0) {
        if (nullability_has(mask, NULLABILITY_BEGIN)) n00b_list_push(*nulls, pos);
        return;
    }
    if (eid == EID_END0) {
        if (nullability_has(mask, NULLABILITY_END)) n00b_list_push(*nulls, pos);
        return;
    }
    const NullStateList *v = &effects->data[eid];
    for (size_t i = 0; i < v->len; ++i) {
        if (nullability_has(v->data[i].mask, mask)) {
            n00b_list_push(*nulls, pos + (size_t)v->data[i].rel);
        }
    }
}

[[gnu::always_inline]] static inline void
collect_max_impl(bool rev, const n00b_list_t(uint16_t) *effects_id,
                 const n00b_list_t(NullStateList) *effects, uint32_t state,
                 size_t pos, Nullability mask, size_t *best)
{
    uint32_t eid = (uint32_t)effects_id->data[state];
    if (eid == EID_NONE) return;
    if (eid == EID_CENTER0) {
        if (nullability_has(mask, NULLABILITY_ALWAYS)) {
            if (rev) *best = usize_min(*best, pos);
            else     *best = usize_max(*best, pos);
        }
        return;
    }
    const NullStateList *v = &effects->data[eid];
    // find rev-first match
    for (size_t i = v->len; i > 0; --i) {
        const NullState *n = &v->data[i - 1];
        if (nullability_has(n->mask, mask)) {
            if (rev) *best = usize_min(*best, pos + (size_t)n->rel);
            else     *best = usize_max(*best, pos - (size_t)n->rel);
            return;
        }
    }
}

[[gnu::always_inline]] static inline void
collect_max_fwd(const n00b_list_t(uint16_t) *effects_id,
                const n00b_list_t(NullStateList) *effects,
                uint32_t state, size_t pos, Nullability mask, size_t *best)
{
    collect_max_impl(false, effects_id, effects, state, pos, mask, best);
}

[[gnu::always_inline]] static inline void
collect_max_rev(const n00b_list_t(uint16_t) *effects_id,
                const n00b_list_t(NullStateList) *effects,
                uint32_t state, size_t pos, Nullability mask, size_t *best)
{
    collect_max_impl(true, effects_id, effects, state, pos, mask, best);
}

void
engine_collect_max_fwd_pub(const n00b_list_t(uint16_t) *effects_id,
                           const n00b_list_t(NullStateList) *effects,
                           uint32_t state, size_t pos, Nullability mask,
                           size_t *best)
{
    collect_max_fwd(effects_id, effects, state, pos, mask, best);
}

void
engine_collect_max_rev_pub(const n00b_list_t(uint16_t) *effects_id,
                           const n00b_list_t(NullStateList) *effects,
                           uint32_t state, size_t pos, Nullability mask,
                           size_t *best)
{
    collect_max_rev(effects_id, effects, state, pos, mask, best);
}

// ===========================================================================
// ScanTables / scan_fwd / scan_fwd_verify / collect_rev (raw-pointer hot loops)
// ===========================================================================

typedef struct ScanTables {
    const uint16_t       *center_table;
    const uint16_t       *center_effect_id;
    const NullStateList  *effects;
    const uint8_t        *data;
    const uint8_t        *minterms_lookup;
    uint32_t              mt_log;
} ScanTables;

[[gnu::cold]] [[gnu::noinline]] static void
collect_rev_center_simple(const NullStateList *effects, uint32_t eid,
                          size_t pos, n00b_list_t(size_t) *nulls)
{
    const NullStateList *v = &effects[eid];
    for (size_t i = 0; i < v->len; ++i) {
        n00b_list_push(*nulls, pos + (size_t)v->data[i].rel);
    }
}

[[gnu::cold]] [[gnu::noinline]] static void
collect_rev_complex(const NullStateList *effects, uint32_t eid,
                    size_t pos, Nullability mask, n00b_list_t(size_t) *nulls)
{
    const NullStateList *v = &effects[eid];
    for (size_t i = 0; i < v->len; ++i) {
        if (nullability_has(v->data[i].mask, mask)) {
            n00b_list_push(*nulls, pos + (size_t)v->data[i].rel);
        }
    }
}

[[gnu::always_inline]] static inline size_t
fwd_update(bool is_end, const uint16_t *effect_id,
           const NullStateList *effects, uint32_t state, size_t pos,
           size_t max_end)
{
    uint16_t eid = effect_id[state];
    if ((uint32_t)eid == EID_NONE) return max_end;
    if ((uint32_t)eid == EID_CENTER0) return usize_max(max_end, pos);
    const NullStateList *v = &effects[eid];
    if (is_end) {
        for (size_t i = v->len; i > 0; --i) {
            const NullState *n = &v->data[i - 1];
            if (nullability_has(n->mask, NULLABILITY_END)) {
                return usize_max(max_end, pos - (size_t)n->rel);
            }
        }
        return max_end;
    }
    if (v->len == 0) return max_end;
    const NullState *n = &v->data[v->len - 1];
    return usize_max(max_end, pos - (size_t)n->rel);
}

// scan_fwd_verify<SKIP>
typedef struct ScanResult {
    uint32_t curr;
    size_t   pos;
    size_t   max_end;
    bool     cache_miss;
} ScanResult;

[[gnu::always_inline]] static inline ScanResult
scan_fwd_verify_inner(bool SKIP, const ScanTables *t,
                      const uint16_t *effects_id,
                      const n00b_list_t(uint8_t) *skip_ids,
                      const n00b_list_t(MintermSearchValue) *skip_searchers,
                      uint32_t curr, size_t pos, size_t end, size_t max_end)
{
    const uint16_t     *center_table     = t->center_table;
    const NullStateList *effects          = t->effects;
    const uint16_t     *center_effect_id = t->center_effect_id;
    const NullStateList *center_effects   = t->effects;
    const uint8_t      *data             = t->data;
    const uint8_t      *minterms_lookup  = t->minterms_lookup;
    uint32_t            mt_log           = t->mt_log;

outer:
    while (pos < end) {
        if (SKIP) {
            uint8_t sid = skip_ids->data[curr];
            if (sid != 0) {
                const MintermSearchValue *searcher = &skip_searchers->data[sid - 1];
                n00b_option_t(size_t) msr = minterm_search_value_find_fwd(
                    searcher, data + pos, end - pos);
                size_t offset = msr.value;
                bool   found  = msr.has_value;
                if (found) {
                    if (offset > 0) {
                        max_end = fwd_update(false, center_effect_id, center_effects,
                                             curr, pos + offset, max_end);
                    }
                    pos += offset;
                }
                else {
                    max_end = fwd_update(true, effects_id, effects, curr, end, max_end);
                    return (ScanResult){ curr, end, max_end, false };
                }
            }
        }

        uint32_t prev_state = curr;
        bool     has_prev   = false;
        while (pos < end) {
            uint32_t mt = (uint32_t)minterms_lookup[data[pos]];
            if (has_prev) {
                max_end = fwd_update(false, center_effect_id, center_effects,
                                     prev_state, pos, max_end);
            }
            size_t   delta = (size_t)((curr << mt_log) | mt);
            uint32_t next  = (uint32_t)center_table[delta];
            if (next == engine_DFA_MISSING) return (ScanResult){ curr, pos, max_end, true };
            if (next == engine_DFA_DEAD)    return (ScanResult){ engine_DFA_DEAD, pos, max_end, false };
            curr       = next;
            prev_state = curr;
            has_prev   = true;
            pos       += 1;
            if (SKIP && skip_ids->data[curr] != 0) {
                if (has_prev) {
                    if (pos >= end) {
                        max_end = fwd_update(true, effects_id, effects, prev_state, pos, max_end);
                    }
                    else {
                        max_end = fwd_update(false, center_effect_id, center_effects,
                                             prev_state, pos, max_end);
                    }
                }
                goto outer;
            }
        }
        if (has_prev) {
            max_end = fwd_update(true, effects_id, effects, prev_state, pos, max_end);
        }
        if (!SKIP) break;
    }
    return (ScanResult){ curr, pos, max_end, false };
}

// Specialized monomorphisations of scan_fwd_verify on SKIP.
static ScanResult
scan_fwd_verify_skip(const ScanTables *t,
                     const uint16_t *effects_id,
                     const n00b_list_t(uint8_t) *skip_ids,
                     const n00b_list_t(MintermSearchValue) *skip_searchers,
                     uint32_t curr, size_t pos, size_t end, size_t max_end)
{
    return scan_fwd_verify_inner(true, t, effects_id, skip_ids, skip_searchers,
                                 curr, pos, end, max_end);
}

static ScanResult
scan_fwd_verify_noskip(const ScanTables *t,
                       const uint16_t *effects_id,
                       uint32_t curr, size_t pos, size_t end, size_t max_end)
{
    return scan_fwd_verify_inner(false, t, effects_id, nullptr, nullptr,
                                 curr, pos, end, max_end);
}

[[gnu::always_inline]] static inline ScanResult
scan_fwd_inner(bool SKIP, const ScanTables *t,
               const uint16_t *effects_id,
               const n00b_list_t(uint8_t) *skip_ids,
               const n00b_list_t(MintermSearchValue) *skip_searchers,
               uint32_t l_state, size_t l_pos, size_t end, size_t max_end)
{
    const uint16_t     *center_table     = t->center_table;
    const NullStateList *effects          = t->effects;
    const uint16_t     *center_effect_id = t->center_effect_id;
    const NullStateList *center_effects   = t->effects;
    const uint8_t      *data             = t->data;
    const uint8_t      *minterms_lookup  = t->minterms_lookup;
    uint32_t            mt_log           = t->mt_log;

    if (l_pos >= end && l_state != engine_DFA_DEAD) {
        max_end = fwd_update(true, effects_id, effects, l_state, end, max_end);
        return (ScanResult){ l_state, end, max_end, false };
    }
    while (l_state != engine_DFA_DEAD) {
        if (SKIP) {
            uint8_t sid = skip_ids->data[l_state];
            if (sid != 0) {
                const MintermSearchValue *searcher = &skip_searchers->data[sid - 1];
                n00b_option_t(size_t) msr = minterm_search_value_find_fwd(
                    searcher, data + l_pos, end - l_pos);
                size_t offset = msr.value;
                bool   found  = msr.has_value;
                if (found && offset > end - l_pos) {
                    fprintf(stderr,
                            "[BAD-OFFSET] sid=%u idx=%u searcher=%p tag=%u as.ptr=%p "
                            "haystack_len=%zu offset=%zu skip_searchers=%p data=%p len=%zu cap=%zu\n",
                            (unsigned)sid, (unsigned)(sid-1), (void*)searcher,
                            (unsigned)minterm_search_value_tag(searcher),
                            (void*)minterm_search_value_exact_bytes(searcher),
                            end - l_pos, offset,
                            (void*)skip_searchers, (void*)skip_searchers->data,
                            skip_searchers->len, skip_searchers->cap);
                }
                if (found) {
                    if (offset > 0) {
                        max_end = fwd_update(false, center_effect_id, center_effects,
                                             l_state, l_pos + offset, max_end);
                    }
                    l_pos += offset;
                }
                else {
                    max_end = fwd_update(true, effects_id, effects, l_state, end, max_end);
                    return (ScanResult){ l_state, end, max_end, false };
                }
            }
        }
        max_end = fwd_update(false, center_effect_id, center_effects,
                             l_state, l_pos, max_end);
        uint32_t mt    = (uint32_t)minterms_lookup[data[l_pos]];
        size_t   delta = (size_t)((l_state << mt_log) | mt);
        uint32_t next  = (uint32_t)center_table[delta];
        if (next == engine_DFA_MISSING) return (ScanResult){ l_state, l_pos, max_end, true };
        if (next == engine_DFA_DEAD)    return (ScanResult){ engine_DFA_DEAD, l_pos, max_end, false };
        l_state  = next;
        l_pos   += 1;
        if (l_pos == end) {
            max_end = fwd_update(true, effects_id, effects, l_state, l_pos, max_end);
            l_state = engine_DFA_DEAD;
        }
    }
    return (ScanResult){ l_state, l_pos, max_end, false };
}

static ScanResult
scan_fwd_skip(const ScanTables *t,
              const uint16_t *effects_id,
              const n00b_list_t(uint8_t) *skip_ids,
              const n00b_list_t(MintermSearchValue) *skip_searchers,
              uint32_t l_state, size_t l_pos, size_t end, size_t max_end)
{
    return scan_fwd_inner(true, t, effects_id, skip_ids, skip_searchers,
                          l_state, l_pos, end, max_end);
}

static ScanResult
scan_fwd_noskip(const ScanTables *t,
                const uint16_t *effects_id,
                uint32_t l_state, size_t l_pos, size_t end, size_t max_end)
{
    return scan_fwd_inner(false, t, effects_id, nullptr, nullptr,
                          l_state, l_pos, end, max_end);
}

typedef struct CollectRevResult {
    uint32_t curr;
    size_t   pos;
    bool     cache_miss;
} CollectRevResult;

[[gnu::always_inline]] static inline CollectRevResult
collect_rev_inner(bool EARLY_EXIT, bool SKIP, bool INITIAL_SKIP,
                  const ScanTables *t,
                  const n00b_list_t(uint8_t) *skip_ids,
                  const n00b_list_t(MintermSearchValue) *skip_searchers,
                  const RevTeddySearch *prefix_ptr,
                  uint32_t curr, size_t pos,
                  const uint8_t *data, size_t data_len,
                  n00b_list_t(size_t) *nulls,
                  uint32_t pruned_id)
{
    const uint16_t     *center_table     = t->center_table;
    const uint16_t     *center_effect_id = t->center_effect_id;
    const uint8_t      *minterms_lookup  = t->minterms_lookup;
    uint32_t            mt_log           = t->mt_log;
    const NullStateList *effects          = t->effects;
    (void)data_len;

    while (pos > 1) {
        if (SKIP) {
            uint8_t sid = skip_ids->data[curr];
            if (sid != 0) {
                if (INITIAL_SKIP && curr == pruned_id) {
                    n00b_option_t(size_t) rpr = n00b_simd_rev_prefix_search_find_rev(
                        prefix_ptr, data, data_len, pos);
                    size_t skip_pos = rpr.value;
                    bool   found    = rpr.has_value;
                    if (found) {
                        if (pos != skip_pos) {
                            pos = skip_pos + 1;
                            uint16_t eid = center_effect_id[curr];
                            if ((uint32_t)eid == EID_CENTER0) {
                                n00b_list_push(*nulls,pos + 1);
                            }
                            else if ((uint32_t)eid != EID_NONE) {
                                collect_rev_center_simple(effects, (uint32_t)eid, pos + 1, nulls);
                            }
                        }
                    }
                    else {
                        pos = 0;
                        continue;
                    }
                }
                else {
                    const MintermSearchValue *searcher = &skip_searchers->data[sid - 1];
                    n00b_option_t(size_t) msr = minterm_search_value_find_rev(
                        searcher, data, pos);
                    size_t skip_pos = msr.value;
                    bool   found    = msr.has_value;
                    if (found) {
                        uint16_t eid = center_effect_id[curr];
                        if ((uint32_t)eid == EID_NONE) {
                            // none
                        }
                        else if ((uint32_t)eid == EID_CENTER0) {
                            for (size_t p = pos; p > skip_pos + 1; --p) {
                                n00b_list_push(*nulls,p - 1);
                            }
                        }
                        else {
                            for (size_t p = pos; p > skip_pos + 1; --p) {
                                collect_rev_center_simple(effects, (uint32_t)eid, p - 1, nulls);
                            }
                        }
                        pos = skip_pos + 1;
                    }
                    else {
                        uint16_t eid = center_effect_id[curr];
                        if ((uint32_t)eid == EID_NONE) {
                            // none
                        }
                        else if ((uint32_t)eid == EID_CENTER0) {
                            for (size_t p = pos; p > 1; --p) {
                                n00b_list_push(*nulls,p - 1);
                            }
                        }
                        else {
                            for (size_t p = pos; p > 1; --p) {
                                collect_rev_center_simple(effects, (uint32_t)eid, p - 1, nulls);
                            }
                        }
                        pos = 1;
                    }
                }
            }
        }
        pos -= 1;
        uint32_t mt   = (uint32_t)minterms_lookup[data[pos]];
        uint32_t next = (uint32_t)center_table[(curr << mt_log) | mt];
        if (next == engine_DFA_MISSING) return (CollectRevResult){ curr, pos, true };
        curr = next;
        uint16_t eid = center_effect_id[curr];
        if ((uint32_t)eid == EID_CENTER0) {
            n00b_list_push(*nulls,pos);
            if (EARLY_EXIT) return (CollectRevResult){ curr, pos, false };
        }
        else if ((uint32_t)eid != EID_NONE) {
            collect_rev_center_simple(effects, (uint32_t)eid, pos, nulls);
            if (EARLY_EXIT && nulls->len > 0) return (CollectRevResult){ curr, pos, false };
        }
    }
    return (CollectRevResult){ curr, 1, false };
}

// Specialised noinline variants.  Reached combinations from the dispatchers:
//   SKIP=true, INITIAL_SKIP=true   (collect_rev_prefix path)
//   SKIP=true, INITIAL_SKIP=false  (collect_rev_inner skip path)
//   SKIP=false                     (no-skip path; INITIAL_SKIP forced to false)
// Each pinned over EARLY_EXIT={false,true}.
[[gnu::noinline]] static CollectRevResult
collect_rev_TT_E0(const ScanTables *t,
                  const n00b_list_t(uint8_t) *skip_ids,
                  const n00b_list_t(MintermSearchValue) *skip_searchers,
                  const RevTeddySearch *prefix_ptr,
                  uint32_t curr, size_t pos,
                  const uint8_t *data, size_t data_len,
                  n00b_list_t(size_t) *nulls, uint32_t pruned_id)
{
    return collect_rev_inner(false, true, true, t, skip_ids, skip_searchers,
                             prefix_ptr, curr, pos, data, data_len, nulls,
                             pruned_id);
}

[[gnu::noinline]] static CollectRevResult
collect_rev_TT_E1(const ScanTables *t,
                  const n00b_list_t(uint8_t) *skip_ids,
                  const n00b_list_t(MintermSearchValue) *skip_searchers,
                  const RevTeddySearch *prefix_ptr,
                  uint32_t curr, size_t pos,
                  const uint8_t *data, size_t data_len,
                  n00b_list_t(size_t) *nulls, uint32_t pruned_id)
{
    return collect_rev_inner(true, true, true, t, skip_ids, skip_searchers,
                             prefix_ptr, curr, pos, data, data_len, nulls,
                             pruned_id);
}

[[gnu::noinline]] static CollectRevResult
collect_rev_TF_E0(const ScanTables *t,
                  const n00b_list_t(uint8_t) *skip_ids,
                  const n00b_list_t(MintermSearchValue) *skip_searchers,
                  uint32_t curr, size_t pos,
                  const uint8_t *data, size_t data_len,
                  n00b_list_t(size_t) *nulls)
{
    return collect_rev_inner(false, true, false, t, skip_ids, skip_searchers,
                             nullptr, curr, pos, data, data_len, nulls, 0);
}

[[gnu::noinline]] static CollectRevResult
collect_rev_TF_E1(const ScanTables *t,
                  const n00b_list_t(uint8_t) *skip_ids,
                  const n00b_list_t(MintermSearchValue) *skip_searchers,
                  uint32_t curr, size_t pos,
                  const uint8_t *data, size_t data_len,
                  n00b_list_t(size_t) *nulls)
{
    return collect_rev_inner(true, true, false, t, skip_ids, skip_searchers,
                             nullptr, curr, pos, data, data_len, nulls, 0);
}

[[gnu::noinline]] static CollectRevResult
collect_rev_F_E0(const ScanTables *t,
                 uint32_t curr, size_t pos,
                 const uint8_t *data, size_t data_len,
                 n00b_list_t(size_t) *nulls)
{
    return collect_rev_inner(false, false, false, t, nullptr, nullptr,
                             nullptr, curr, pos, data, data_len, nulls, 0);
}

[[gnu::noinline]] static CollectRevResult
collect_rev_F_E1(const ScanTables *t,
                 uint32_t curr, size_t pos,
                 const uint8_t *data, size_t data_len,
                 n00b_list_t(size_t) *nulls)
{
    return collect_rev_inner(true, false, false, t, nullptr, nullptr,
                             nullptr, curr, pos, data, data_len, nulls, 0);
}

// ===========================================================================
// LDFA dispatchers
// ===========================================================================

static ScanTables
engine_LDFA_scan_tables(const LDFA *self, const uint8_t *data)
{
    return (ScanTables){
        .center_table     = self->center_table.data,
        .effects          = self->effects.data,
        .center_effect_id = self->center_effect_id.data,
        .data             = data,
        .minterms_lookup  = self->mt_lookup,
        .mt_log           = self->mt_log,
    };
}

bool
engine_LDFA_can_skip(const LDFA *self)
{
    return self->prefix_skip.present || self->skip_searchers.len != 0;
}

static ScanResult
engine_LDFA_dispatch_scan_fwd(const LDFA *self,
                              const ScanTables *tables,
                              uint32_t curr, size_t pos,
                              size_t end, size_t max_end)
{
    if (engine_LDFA_can_skip(self)) {
        return scan_fwd_skip(tables, self->effects_id.data,
                             &self->skip_ids, &self->skip_searchers,
                             curr, pos, end, max_end);
    }
    return scan_fwd_noskip(tables, self->effects_id.data,
                           curr, pos, end, max_end);
}

static ScanResult
engine_LDFA_dispatch_scan_fwd_verify(const LDFA *self,
                                     const ScanTables *tables,
                                     uint32_t curr, size_t pos,
                                     size_t end, size_t max_end)
{
    if (engine_LDFA_can_skip(self)) {
        return scan_fwd_verify_skip(tables, self->effects_id.data,
                                    &self->skip_ids, &self->skip_searchers,
                                    curr, pos, end, max_end);
    }
    return scan_fwd_verify_noskip(tables, self->effects_id.data,
                                  curr, pos, end, max_end);
}

static CollectRevResult
engine_LDFA_dispatch_collect_rev(const LDFA *self,
                                 bool EARLY_EXIT, bool INITIAL_SKIP,
                                 const ScanTables *tables,
                                 const RevTeddySearch *prefix_ptr,
                                 uint32_t curr, size_t pos,
                                 const uint8_t *data, size_t data_len,
                                 n00b_list_t(size_t) *nulls)
{
    if (engine_LDFA_can_skip(self)) {
        if (INITIAL_SKIP) {
            if (EARLY_EXIT) {
                return collect_rev_TT_E1(tables, &self->skip_ids,
                                         &self->skip_searchers, prefix_ptr,
                                         curr, pos, data, data_len, nulls,
                                         (uint32_t)self->pruned);
            }
            return collect_rev_TT_E0(tables, &self->skip_ids,
                                     &self->skip_searchers, prefix_ptr,
                                     curr, pos, data, data_len, nulls,
                                     (uint32_t)self->pruned);
        }
        if (EARLY_EXIT) {
            return collect_rev_TF_E1(tables, &self->skip_ids,
                                     &self->skip_searchers,
                                     curr, pos, data, data_len, nulls);
        }
        return collect_rev_TF_E0(tables, &self->skip_ids,
                                 &self->skip_searchers,
                                 curr, pos, data, data_len, nulls);
    }
    if (EARLY_EXIT) {
        return collect_rev_F_E1(tables, curr, pos, data, data_len, nulls);
    }
    return collect_rev_F_E0(tables, curr, pos, data, data_len, nulls);
}

// ===========================================================================
// LDFA::scan_fwd_slow / scan_fwd_all / walk_input / scan_fwd_from / scan_rev_from
// ===========================================================================

static size_t
engine_LDFA_resolve_max_end(size_t max_end, bool has_empty, size_t pos_begin)
{
    if (max_end > 0) return max_end;
    if (has_empty)   return pos_begin;
    return engine_NO_MATCH;
}

n00b_result_t(size_t)
engine_LDFA_scan_fwd_slow(LDFA *self, RegexBuilder *b, size_t pos_begin,
                          const uint8_t *data, size_t data_len)
{
    Nullability empty_mask = pos_begin == 0 ? NULLABILITY_BEGIN : NULLABILITY_CENTER;
    bool has_empty = engine_has_any_null(&self->effects_id, &self->effects,
                                          (uint32_t)engine_DFA_INITIAL, empty_mask);

    uint8_t  mt   = self->mt_lookup[data[pos_begin]];
    uint32_t curr = (uint32_t)self->begin_table.data[mt];
    if (curr <= engine_DFA_DEAD) {
        return n00b_result_ok(size_t, has_empty ? pos_begin : engine_NO_MATCH);
    }
    size_t end     = data_len;
    size_t pos     = pos_begin + 1;
    size_t max_end = 0;

    Nullability mask = (pos == end) ? NULLABILITY_END : NULLABILITY_CENTER;
    collect_max_fwd(&self->effects_id, &self->effects, curr, pos, mask, &max_end);
    if (pos == end) {
        return n00b_result_ok(size_t, engine_LDFA_resolve_max_end(max_end, has_empty, pos_begin));
    }

    for (;;) {
        ScanTables tables = engine_LDFA_scan_tables(self, data);
        ScanResult r      = engine_LDFA_dispatch_scan_fwd(self, &tables, curr, pos, end, max_end);
        max_end = r.max_end;
        if (!r.cache_miss) break;
        uint16_t sid = (uint16_t)r.curr;
        n00b_result_t(int) cs = engine_LDFA_create_state(self, b, (uint32_t)sid);
        if (n00b_result_is_err(cs)) {
            return n00b_result_err(size_t, n00b_result_get_err(cs));
        }
        uint32_t mt2 = (uint32_t)self->mt_lookup[data[r.pos]];
        curr = (uint32_t)self->center_table.data[engine_LDFA_dfa_delta(self, sid, mt2)];
        pos  = r.pos + 1;
        if (curr <= engine_DFA_DEAD) break;
        n00b_result_t(int) cs2 = engine_LDFA_create_state(self, b, curr);
        if (n00b_result_is_err(cs2)) {
            return n00b_result_err(size_t, n00b_result_get_err(cs2));
        }
        Nullability m2 = (pos == end) ? NULLABILITY_END : NULLABILITY_CENTER;
        collect_max_fwd(&self->effects_id, &self->effects, curr, pos, m2, &max_end);
        if (pos == end) break;
    }
    return n00b_result_ok(size_t, engine_LDFA_resolve_max_end(max_end, has_empty, pos_begin));
}

[[gnu::noinline]] n00b_result_t(int)
engine_LDFA_scan_fwd_all(LDFA *self, RegexBuilder *b,
                         const n00b_list_t(size_t) *nulls_vec,
                         const uint8_t *data, size_t data_len,
                         n00b_list_t(Match) *matches)
{
    const size_t * volatile nulls     = nulls_vec->data;
    size_t        nulls_len = nulls_vec->len;
    if (nulls_len == 0) return n00b_result_ok(int, 0);
    size_t data_end   = data_len;
    size_t next_start = 0;
    size_t l_pos;
    size_t i = nulls_len;

    if (nulls[nulls_len - 1] == 0) {
        i -= 1;
        l_pos              = 0;
        size_t   l_max_end = 0;
        uint32_t mt        = (uint32_t)self->mt_lookup[data[l_pos]];
        uint32_t l_state   = (uint32_t)self->begin_table.data[mt];
        l_pos              = 1;

        for (;;) {
            ScanTables tables = engine_LDFA_scan_tables(self, data);
            ScanResult r      = engine_LDFA_dispatch_scan_fwd(self, &tables, l_state, l_pos, data_end, l_max_end);
            l_max_end = r.max_end;
            if (r.cache_miss) {
                uint32_t flush_state;
                size_t   flush_pos;
                if (r.pos >= data_end) {
                    flush_state = r.curr;
                    flush_pos   = r.pos;
                }
                else {
                    uint32_t mt2 = (uint32_t)self->mt_lookup[data[r.pos]];
                    n00b_result_t(uint32_t) lt = engine_LDFA_lazy_transition(self, b, r.curr, mt2);
                    if (n00b_result_is_err(lt)) {
                        return n00b_result_err(int, n00b_result_get_err(lt));
                    }
                    uint32_t new_state = n00b_result_get(lt);
                    l_pos   = r.pos + 1;
                    l_state = new_state;
                    if (l_pos != data_end) continue;
                    flush_state = new_state;
                    flush_pos   = l_pos;
                }
                l_max_end = fwd_update(true, self->effects_id.data, self->effects.data,
                                       flush_state, flush_pos, l_max_end);
            }
            n00b_list_push(*matches, ((Match){ .start = 0, .end = l_max_end }));
            // Zero-width match: advance the non-overlap cursor PAST the
            // position so a duplicate null seed at 0 cannot re-emit it.
            next_start = l_max_end > 0 ? l_max_end : 1;
            break;
        }
    }

    while (i != 0) {
        i -= 1;
        l_pos = nulls[i];
        if (l_pos < next_start) continue;
        if (l_pos == data_end) {
            n00b_list_push(*matches, ((Match){ .start = l_pos, .end = l_pos }));
            break;
        }
        uint32_t l_state   = (uint32_t)engine_DFA_INITIAL;
        size_t   l_max_end = 0;
        for (;;) {
            ScanTables tables = engine_LDFA_scan_tables(self, data);
            ScanResult r      = engine_LDFA_dispatch_scan_fwd(self, &tables, l_state, l_pos, data_end, l_max_end);
            l_max_end = r.max_end;
            if (r.cache_miss) {
                n00b_require(r.pos >= l_pos,
                             "engine_LDFA_scan_fwd_all: scan_fwd returned r.pos < l_pos");
                uint32_t mt2 = (uint32_t)self->mt_lookup[data[r.pos]];
                n00b_result_t(uint32_t) lt = engine_LDFA_lazy_transition(self, b, r.curr, mt2);
                if (n00b_result_is_err(lt)) {
                    return n00b_result_err(int, n00b_result_get_err(lt));
                }
                uint32_t next_state = n00b_result_get(lt);
                l_pos   = r.pos + 1;
                l_state = next_state;
                if (l_pos != data_end) continue;
                l_max_end = fwd_update(true, self->effects_id.data, self->effects.data,
                                       l_state, l_pos, l_max_end);
                n00b_list_push(*matches, ((Match){ .start = nulls[i], .end = l_max_end }));
                // Zero-width match (end == start): advance the cursor PAST the
                // position so a duplicate null seed at the same position cannot
                // re-emit the same empty match.
                next_start = l_max_end > nulls[i] ? l_max_end : nulls[i] + 1;
                break;
            }
            n00b_require(l_max_end >= nulls[i],
                         "engine_LDFA_scan_fwd_all: l_max_end retreated below null seed");
            n00b_list_push(*matches, ((Match){ .start = nulls[i], .end = l_max_end }));
            // Zero-width match (end == start): advance the cursor PAST the
            // position so a duplicate null seed at the same position cannot
            // re-emit the same empty match.
            next_start = l_max_end > nulls[i] ? l_max_end : nulls[i] + 1;
            break;
        }
    }
    return n00b_result_ok(int, 0);
}

n00b_result_t(uint32_t)
engine_LDFA_walk_input(LDFA *self, RegexBuilder *b, size_t pos, size_t len,
                       const uint8_t *data, size_t data_len)
{
    (void)data_len;
    uint32_t state;
    size_t   start_i;
    if (pos == 0) {
        uint8_t mt = self->mt_lookup[data[pos]];
        state   = (uint32_t)self->begin_table.data[mt];
        start_i = 1;
    }
    else {
        state   = (uint32_t)self->pruned;
        start_i = 0;
    }
    if (state <= engine_DFA_DEAD) return n00b_result_ok(uint32_t, 0);
    for (size_t i = start_i; i < len; ++i) {
        uint32_t mt = (uint32_t)self->mt_lookup[data[pos + i]];
        n00b_result_t(uint32_t) lt = engine_LDFA_lazy_transition(self, b, state, mt);
        if (n00b_result_is_err(lt)) {
            return n00b_result_err(uint32_t, n00b_result_get_err(lt));
        }
        state = n00b_result_get(lt);
        if (state <= engine_DFA_DEAD) return n00b_result_ok(uint32_t, 0);
    }
    return n00b_result_ok(uint32_t, state);
}

n00b_result_t(size_t)
engine_LDFA_scan_fwd_from(LDFA *self, RegexBuilder *b, uint32_t state,
                          size_t pos_begin, const uint8_t *data,
                          size_t data_len)
{
    if (state <= engine_DFA_DEAD) return n00b_result_ok(size_t, engine_NO_MATCH);
    size_t   end     = data_len;
    size_t   pos     = pos_begin;
    uint32_t curr    = state;
    size_t   max_end = 0;

    collect_max_fwd(&self->effects_id, &self->effects, curr, pos,
                    NULLABILITY_CENTER, &max_end);
    if (pos >= end) {
        collect_max_fwd(&self->effects_id, &self->effects, curr, pos,
                        NULLABILITY_END, &max_end);
        return n00b_result_ok(size_t, max_end > 0 ? max_end : engine_NO_MATCH);
    }

    for (;;) {
        ScanTables tables = engine_LDFA_scan_tables(self, data);
        ScanResult r      = engine_LDFA_dispatch_scan_fwd_verify(self, &tables, curr, pos, end, max_end);
        max_end = r.max_end;
        if (!r.cache_miss) break;
        uint32_t mt = (uint32_t)self->mt_lookup[data[r.pos]];
        n00b_result_t(uint32_t) lt = engine_LDFA_lazy_transition(self, b, r.curr, mt);
        if (n00b_result_is_err(lt)) {
            return n00b_result_err(size_t, n00b_result_get_err(lt));
        }
        curr = n00b_result_get(lt);
        pos  = r.pos + 1;
        if (curr <= engine_DFA_DEAD) break;
        // Best-effort create_state; ignore failure.
        n00b_result_t(int) cs = engine_LDFA_create_state(self, b, curr);
        (void)cs;  // result intentionally discarded
        Nullability m2 = (pos >= end) ? NULLABILITY_END : NULLABILITY_CENTER;
        collect_max_fwd(&self->effects_id, &self->effects, curr, pos, m2, &max_end);
        if (pos >= end) break;
    }
    return n00b_result_ok(size_t, max_end > 0 ? max_end : engine_NO_MATCH);
}

// scan_fwd_first_null<SKIP>
typedef struct FirstNullResult {
    uint32_t state;
    size_t   pos;
    bool     hit_null;
    bool     cache_miss;
} FirstNullResult;

[[gnu::always_inline]] static inline FirstNullResult
scan_fwd_first_null_body(bool SKIP, const ScanTables *t,
                         const uint16_t *effects_id,
                         const n00b_list_t(uint8_t) *skip_ids,
                         const n00b_list_t(MintermSearchValue) *skip_searchers,
                         uint32_t curr, size_t pos, size_t end)
{
    const uint16_t *center_table    = t->center_table;
    const uint8_t  *data            = t->data;
    const uint8_t  *minterms_lookup = t->minterms_lookup;
    uint32_t        mt_log          = t->mt_log;

outer:
    while (pos < end) {
        if (SKIP) {
            uint8_t sid = skip_ids->data[curr];
            if (sid != 0) {
                const MintermSearchValue *searcher = &skip_searchers->data[sid - 1];
                n00b_option_t(size_t) msr = minterm_search_value_find_fwd(
                    searcher, data + pos, end - pos);
                if (msr.has_value) {
                    pos += msr.value;
                }
                else {
                    return (FirstNullResult){ curr, end, false, false };
                }
            }
        }
        while (pos < end) {
            uint32_t mt    = (uint32_t)minterms_lookup[data[pos]];
            size_t   delta = (size_t)((curr << mt_log) | mt);
            uint32_t next  = (uint32_t)center_table[delta];
            if (next == engine_DFA_MISSING)
                return (FirstNullResult){ curr, pos, false, true };
            if (next == engine_DFA_DEAD)
                return (FirstNullResult){ engine_DFA_DEAD, pos, false, false };
            curr = next;
            pos += 1;
            uint32_t eid = (uint32_t)effects_id[curr];
            // Mirror upstream: skip BEGIN0 / END0 sentinels, only treat
            // non-trivial CENTER-bearing nulls as hit.
            if (eid != 0 && eid != EID_BEGIN0 && eid != EID_END0) {
                return (FirstNullResult){ curr, pos, true, false };
            }
            if (SKIP && skip_ids->data[curr] != 0) {
                goto outer;
            }
        }
        if (!SKIP) break;
    }
    return (FirstNullResult){ curr, pos, false, false };
}

static FirstNullResult
scan_fwd_first_null_skip(const ScanTables *t,
                         const uint16_t *effects_id,
                         const n00b_list_t(uint8_t) *skip_ids,
                         const n00b_list_t(MintermSearchValue) *skip_searchers,
                         uint32_t curr, size_t pos, size_t end)
{
    return scan_fwd_first_null_body(true, t, effects_id, skip_ids,
                                    skip_searchers, curr, pos, end);
}

static FirstNullResult
scan_fwd_first_null_noskip(const ScanTables *t,
                           const uint16_t *effects_id,
                           uint32_t curr, size_t pos, size_t end)
{
    return scan_fwd_first_null_body(false, t, effects_id, nullptr, nullptr,
                                    curr, pos, end);
}

n00b_result_t(EngineFirstNullOut)
engine_LDFA_scan_fwd_first_null_from(LDFA *self, RegexBuilder *b,
                                     uint32_t state, size_t pos_begin,
                                     const uint8_t *data, size_t data_len)
{
    if (state <= engine_DFA_DEAD) {
        return n00b_result_ok(EngineFirstNullOut,
            ((EngineFirstNullOut){ .state = state, .pos = pos_begin, .hit_null = false }));
    }
    if (engine_has_any_null(&self->effects_id, &self->effects, state, NULLABILITY_CENTER)) {
        return n00b_result_ok(EngineFirstNullOut,
            ((EngineFirstNullOut){ .state = state, .pos = pos_begin, .hit_null = true }));
    }
    size_t   end  = data_len;
    size_t   pos  = pos_begin;
    uint32_t curr = state;
    if (pos >= end) {
        return n00b_result_ok(EngineFirstNullOut,
            ((EngineFirstNullOut){ .state = curr, .pos = pos, .hit_null = false }));
    }
    for (;;) {
        ScanTables       tables = engine_LDFA_scan_tables(self, data);
        FirstNullResult r;
        if (engine_LDFA_can_skip(self)) {
            r = scan_fwd_first_null_skip(&tables, self->effects_id.data,
                                         &self->skip_ids, &self->skip_searchers,
                                         curr, pos, end);
        }
        else {
            r = scan_fwd_first_null_noskip(&tables, self->effects_id.data,
                                           curr, pos, end);
        }
        if (r.hit_null) {
            return n00b_result_ok(EngineFirstNullOut,
                ((EngineFirstNullOut){ .state = r.state, .pos = r.pos, .hit_null = true }));
        }
        if (!r.cache_miss) {
            return n00b_result_ok(EngineFirstNullOut,
                ((EngineFirstNullOut){ .state = r.state, .pos = r.pos, .hit_null = false }));
        }
        // cache miss: lazy_transition + create_state, then loop
        uint32_t mt = (uint32_t)self->mt_lookup[data[r.pos]];
        n00b_result_t(uint32_t) lt = engine_LDFA_lazy_transition(self, b, r.state, mt);
        if (n00b_result_is_err(lt)) {
            return n00b_result_err(EngineFirstNullOut, n00b_result_get_err(lt));
        }
        curr = n00b_result_get(lt);
        pos  = r.pos + 1;
        if (curr <= engine_DFA_DEAD) {
            return n00b_result_ok(EngineFirstNullOut,
                ((EngineFirstNullOut){ .state = curr, .pos = pos, .hit_null = false }));
        }
        // Best-effort create_state; ignore failure.
        (void)engine_LDFA_create_state(self, b, curr);
        if (engine_has_any_null(&self->effects_id, &self->effects, curr, NULLABILITY_CENTER)) {
            return n00b_result_ok(EngineFirstNullOut,
                ((EngineFirstNullOut){ .state = curr, .pos = pos, .hit_null = true }));
        }
        if (pos >= end) {
            return n00b_result_ok(EngineFirstNullOut,
                ((EngineFirstNullOut){ .state = curr, .pos = pos, .hit_null = false }));
        }
    }
}

n00b_result_t(size_t)
engine_LDFA_scan_rev_from(LDFA *self, RegexBuilder *b,
                          size_t end, size_t begin,
                          const uint8_t *data, size_t data_len)
{
    if (end == 0 || end > data_len || end <= begin) {
        return n00b_result_ok(size_t, engine_NO_MATCH);
    }
    size_t   start_pos = end - 1;
    uint32_t mt        = (uint32_t)self->mt_lookup[data[start_pos]];
    uint32_t curr      = (uint32_t)self->begin_table.data[mt];
    if (curr <= engine_DFA_DEAD) {
        return n00b_result_ok(size_t, engine_NO_MATCH);
    }

    size_t      min_start = engine_NO_MATCH;
    Nullability mask      = (start_pos == begin) ? NULLABILITY_END : NULLABILITY_CENTER;
    collect_max_rev(&self->effects_id, &self->effects, curr, start_pos, mask, &min_start);

    size_t pos = start_pos;
    while (pos > begin) {
        pos -= 1;
        uint32_t mt2   = (uint32_t)self->mt_lookup[data[pos]];
        size_t   delta = (size_t)((curr << self->mt_log) | mt2);
        uint16_t next  = self->center_table.data[delta];
        if (next == engine_DFA_MISSING) {
            n00b_result_t(uint32_t) lt = engine_LDFA_lazy_transition(self, b, curr, mt2);
            if (n00b_result_is_err(lt)) {
                return n00b_result_err(size_t, n00b_result_get_err(lt));
            }
            curr = n00b_result_get(lt);
            // Best-effort create_state; ignore failure.
            (void)engine_LDFA_create_state(self, b, curr);
        }
        else {
            curr = (uint32_t)next;
        }
        if (curr <= engine_DFA_DEAD) break;
        Nullability m2 = (pos == begin) ? NULLABILITY_END : NULLABILITY_CENTER;
        collect_max_rev(&self->effects_id, &self->effects, curr, pos, m2, &min_start);
    }
    return n00b_result_ok(size_t, min_start);
}

// ===========================================================================
// LDFA::collect_rev / collect_rev_first / len_1_rev / handle_rev_end
// ===========================================================================

static n00b_result_t(int)
engine_LDFA_handle_rev_end(LDFA *self, RegexBuilder *b, uint16_t sid,
                           const uint8_t *data, n00b_list_t(size_t) *nulls)
{
    uint32_t mt = (uint32_t)self->mt_lookup[data[0]];
    n00b_result_t(uint32_t) lt = engine_LDFA_lazy_transition(self, b, (uint32_t)sid, mt);
    if (n00b_result_is_err(lt)) {
        return n00b_result_err(int, n00b_result_get_err(lt));
    }
    uint32_t new_state = n00b_result_get(lt);
    uint32_t effect    = (uint32_t)self->effects_id.data[new_state];
    collect_rev_complex(self->effects.data, effect, 0, NULLABILITY_END, nulls);
    return n00b_result_ok(int, 0);
}

static n00b_result_t(int)
engine_LDFA_collect_rev_prefix(LDFA *self, bool EARLY_EXIT, RegexBuilder *b,
                               const RevTeddySearch *prefix_ptr,
                               size_t start_pos, uint32_t start_state,
                               const uint8_t *data, size_t data_len,
                               n00b_list_t(size_t) *nulls)
{
    uint32_t curr = start_state;
    size_t   pos  = start_pos;
    if (EARLY_EXIT && nulls->len > 0) return n00b_result_ok(int, 0);
    if (!self->has_anchors) {
        pos  = data_len;
        curr = (uint32_t)self->pruned;
    }
    for (;;) {
        ScanTables       tables = engine_LDFA_scan_tables(self, data);
        CollectRevResult r      = engine_LDFA_dispatch_collect_rev(
            self, EARLY_EXIT, true, &tables, prefix_ptr,
            curr, pos, data, data_len, nulls);
        if (EARLY_EXIT && nulls->len > 0) return n00b_result_ok(int, 0);
        if (r.cache_miss) {
            uint16_t sid = (uint16_t)r.curr;
            n00b_result_t(int) cs = engine_LDFA_create_state(self, b, (uint32_t)sid);
            if (n00b_result_is_err(cs)) {
                return n00b_result_err(int, n00b_result_get_err(cs));
            }
            curr = (uint32_t)sid;
            pos  = r.pos + 1;
            continue;
        }
        return engine_LDFA_handle_rev_end(self, b, (uint16_t)r.curr, data, nulls);
    }
}

static n00b_result_t(int)
engine_LDFA_collect_rev_inner(LDFA *self, bool EARLY_EXIT,
                              RegexBuilder *b, size_t start_pos,
                              const uint8_t *data, size_t data_len,
                              n00b_list_t(size_t) *nulls)
{
    uint32_t curr = (uint32_t)self->begin_table.data[self->mt_lookup[data[start_pos]]];
    if (data_len == 1) return engine_LDFA_len_1_rev(self, curr, nulls);
    collect_nulls(&self->effects_id, &self->effects, curr, start_pos,
                  NULLABILITY_CENTER, nulls);

    if (self->prefix_skip.present) {
        return engine_LDFA_collect_rev_prefix(self, EARLY_EXIT, b,
                                              self->prefix_skip.value,
                                              start_pos, curr, data, data_len, nulls);
    }
    if (EARLY_EXIT && nulls->len > 0) return n00b_result_ok(int, 0);
    size_t pos = start_pos;
    for (;;) {
        ScanTables       tables = engine_LDFA_scan_tables(self, data);
        CollectRevResult r      = engine_LDFA_dispatch_collect_rev(
            self, EARLY_EXIT, false, &tables, nullptr,
            curr, pos, data, data_len, nulls);
        if (EARLY_EXIT && nulls->len > 0) return n00b_result_ok(int, 0);
        if (!r.cache_miss) {
            return engine_LDFA_handle_rev_end(self, b, (uint16_t)r.curr, data, nulls);
        }
        uint16_t sid = (uint16_t)r.curr;
        n00b_result_t(int) cs = engine_LDFA_create_state(self, b, (uint32_t)sid);
        if (n00b_result_is_err(cs)) {
            return n00b_result_err(int, n00b_result_get_err(cs));
        }
        uint32_t mt    = (uint32_t)self->mt_lookup[data[r.pos]];
        size_t   delta = engine_LDFA_dfa_delta(self, sid, mt);
        curr = (uint32_t)self->center_table.data[delta];
        pos  = r.pos;
        if (curr <= engine_DFA_DEAD) break;
        Nullability mask = (pos == 0) ? NULLABILITY_END : NULLABILITY_CENTER;
        collect_nulls(&self->effects_id, &self->effects, curr, pos, mask, nulls);
        if (EARLY_EXIT && nulls->len > 0) return n00b_result_ok(int, 0);
    }
    return n00b_result_ok(int, 0);
}

n00b_result_t(int)
engine_LDFA_collect_rev(LDFA *self, RegexBuilder *b, size_t start_pos,
                        const uint8_t *data, size_t data_len, n00b_list_t(size_t) *nulls)
{
    return engine_LDFA_collect_rev_inner(self, false, b, start_pos, data, data_len, nulls);
}

n00b_result_t(int)
engine_LDFA_collect_rev_first(LDFA *self, RegexBuilder *b, size_t start_pos,
                              const uint8_t *data, size_t data_len, n00b_list_t(size_t) *nulls)
{
    return engine_LDFA_collect_rev_inner(self, true, b, start_pos, data, data_len, nulls);
}

[[gnu::cold]] n00b_result_t(int)
engine_LDFA_len_1_rev(LDFA *self, uint32_t curr, n00b_list_t(size_t) *nulls)
{
    collect_nulls(&self->effects_id, &self->effects, curr, 0, NULLABILITY_END, nulls);
    return n00b_result_ok(int, 0);
}

// ===========================================================================
// Engine ABI accessors / public destructor / external constants.
// ===========================================================================

const size_t   engine_NO_MATCH    = SIZE_MAX;
const uint32_t engine_DFA_MISSING = 0;
const uint32_t engine_DFA_DEAD    = 1;
const uint32_t engine_DFA_INITIAL = 2;

// EID_* — derived from algebra's NullsId sentinels.
const uint32_t EID_NONE    = 0;  // matches NULLS_ID_EMPTY.v
const uint32_t EID_CENTER0 = 1;  // matches NULLS_ID_CENTER0.v
const uint32_t EID_ALWAYS0 = 2;  // matches NULLS_ID_ALWAYS0.v
const uint32_t EID_BEGIN0  = 3;  // matches NULLS_ID_BEGIN0.v
const uint32_t EID_END0    = 4;  // matches NULLS_ID_END0.v

void
engine_LDFA_free(LDFA *self)
{
    if (!self) return;
    engine_LDFA_drop(self);
    n00b_free(self);
}

// LDFA field accessors.
const uint8_t *
engine_LDFA_mt_lookup(const LDFA *l)
{
    return l->mt_lookup;
}

const uint16_t *
engine_LDFA_begin_table(const LDFA *l)
{
    return l->begin_table.data;
}

uint16_t
engine_LDFA_pruned(const LDFA *l)
{
    return l->pruned;
}

const n00b_list_t(uint16_t) *
engine_LDFA_effects_id(const LDFA *l)
{
    return &l->effects_id;
}

size_t
engine_LDFA_effects_id_len(const LDFA *l)
{
    return l->effects_id.len;
}

const n00b_list_t(NullStateList) *
engine_LDFA_effects(const LDFA *l)
{
    return &l->effects;
}

size_t
engine_LDFA_state_nodes_len(const LDFA *l)
{
    return l->state_nodes.len;
}

void
engine_LDFA_set_prefix_skip(LDFA *l, RevTeddySearch *skip)
{
    l->prefix_skip.present = (skip != nullptr);
    l->prefix_skip.value   = skip;
}

RevTeddySearch *
engine_LDFA_get_prefix_skip(const LDFA *l)
{
    return l->prefix_skip.present ? l->prefix_skip.value : nullptr;
}

uint32_t
engine_LDFA_mt_log(const LDFA *self)
{
    return self->mt_log;
}

uint16_t
engine_LDFA_effects_id_at(const LDFA *self, size_t idx)
{
    return self->effects_id.data[idx];
}

uint16_t
engine_LDFA_mt_lookup_at(const LDFA *self, size_t idx)
{
    return self->mt_lookup[idx];
}

uint16_t
engine_LDFA_begin_table_at(const LDFA *self, size_t idx)
{
    return self->begin_table.data[idx];
}

size_t
engine_LDFA_effects_len(const LDFA *self, uint32_t eid)
{
    return self->effects.data[eid].len;
}

void
engine_LDFA_effects_get(const LDFA *self, uint32_t eid, size_t i, NullState *out)
{
    *out = self->effects.data[eid].data[i];
}

// engine_LDFA_scan_fwd_active_set_{true,false} adapters around fas.c's
// LDFA_scan_fwd_active_set_{always_nullable,general}.

n00b_result_t(int)
engine_LDFA_scan_fwd_active_set_true(LDFA *self, RegexBuilder *b,
                                     FwdDFA *fas,
                                     const uint8_t *input, size_t input_len,
                                     const n00b_list_t(size_t) *nulls,
                                     n00b_list_t(Match) *matches)
{
    return LDFA_scan_fwd_active_set_always_nullable(
        self, b, fas, input, input_len,
        nulls->data, nulls->len, matches);
}

n00b_result_t(int)
engine_LDFA_scan_fwd_active_set_false(LDFA *self, RegexBuilder *b,
                                      FwdDFA *fas,
                                      const uint8_t *input, size_t input_len,
                                      const n00b_list_t(size_t) *nulls,
                                      n00b_list_t(Match) *matches)
{
    return LDFA_scan_fwd_active_set_general(
        self, b, fas, input, input_len,
        nulls->data, nulls->len, matches);
}
