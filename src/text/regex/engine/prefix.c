// prefix.c — forward / reverse literal-prefix extraction.
//
// Per section 0a-Z of the port plan: typed translation of the algorithm
// from upstream Rust resharp `prefix`, with resharp-c's allocation /
// hashset / error / overflow-checked-arithmetic shims replaced by n00b
// primitives:
//
//   resharp-c xalloc family   -> n00b_alloc / n00b_alloc_array / n00b_free;
//                                geometric grow via alloc-new + memcpy
//                                (D13) + free-old.
//   resharp-c ckd helpers     -> stdckdint.h ckd_mul / ckd_add (section
//                                15(C)), wrapped by safe_mul_sz /
//                                safe_add_sz that route to n00b_panic on
//                                overflow.
//   resharp-c HASHSET<NodeId> -> n00b_dict_t(NodeId, bool) with
//                                .skip_obj_hash = true (4-byte POD key).
//   Vec<TSetId> / Vec<u8> / Vec<NodeId>
//                             -> caller-managed {data,len,cap} structs,
//                                single-owner, grown via the same
//                                alloc-new + memcpy + free-old pattern
//                                (mirrors algebra/nulls.c).
//   resharp-c Error*          -> int err side of n00b_result_t (D14);
//                                algebra now returns
//                                n00b_result_t(NodeId|TRegexId) directly
//                                (no out-param), so the
//                                `error_from_algebra` shim disappears.
//   resharp-c panic / require / unreachable macros
//                             -> n00b_panic / n00b_require /
//                                n00b_unreachable (D8/D9/D10).
//
// Algorithmic vocabulary (PrefixSet, PrefixSets, PrefixKind,
// calc_prefix_sets, select_prefix, …) stays un-prefixed — this is the
// regex algebra's vocabulary, not user-facing API.

#include "n00b.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdckdint.h>
#include <math.h>           // INFINITY for the cost-model fire estimate
#include <string.h>         // memcpy / memset / memmove (D13)

#include "core/alloc.h"
#include "adt/dict.h"
#include "util/assert.h"
#include "util/panic.h"

#include "internal/regex/prefix.h"
#include "internal/regex/algebra.h"
#include "internal/regex/solver.h"
#include "internal/regex/nulls.h"
#include "internal/regex/accel.h"
#include "internal/regex/fas.h" // n00b_regex_engine_err_t
#include "internal/regex/ids.h"

// ===========================================================================
// Algebra-internal RegexBuilder helpers — declared in algebra.h but listed
// here for the few that prefix.c uses extensively across this TU.  The
// algebra TU provides the definitions.
// ===========================================================================
//
// (No re-declarations needed — the includes above bring in every signature.)

// ===========================================================================
// Engine accel/simd hooks — not yet in any C header.  Phase 8/10 SIMD
// will provide the definitions; declared here as externs so the engine
// TU links until then.  Signatures match the upstream Rust shapes,
// adapted to the typed `FwdPrefixSearchSimd` / `FwdRangeSearch` /
// `RevTeddySearch` / `FwdLiteralSearch` opaques declared in accel.h.
// ===========================================================================

extern FwdLiteralSearch *n00b_simd_FwdLiteralSearch_new(const uint8_t *needle, size_t len);
extern uint8_t           n00b_simd_FwdLiteralSearch_rare_byte(const FwdLiteralSearch *l);
extern void              n00b_simd_FwdLiteralSearch_free(FwdLiteralSearch *l);

extern FwdPrefixSearchSimd *
n00b_simd_FwdPrefixSearch_new(size_t total_len,
                         const size_t *freq_order, size_t freq_order_len,
                         const ByteVec *byte_sets, size_t byte_sets_len,
                         const TSet *all_sets, size_t all_sets_len);

extern FwdRangeSearch *
n00b_simd_FwdRangeSearch_new(size_t total_len,
                        size_t anchor_pos,
                        const uint8_t *lo, const uint8_t *hi, size_t ranges_len,
                        const TSet *all_sets, size_t all_sets_len);

extern RevTeddySearch *
n00b_simd_RevTeddySearch_new(size_t num_simd,
                        const ByteVec *window, size_t window_len,
                        const TSet *all_sets, size_t all_sets_len,
                        size_t tail_offset);

// ===========================================================================
// Small overflow-checked size_t helpers (mirrors algebra/nulls.c).
// ===========================================================================

[[noreturn]] static inline void prefix_capacity_overflow(void)
{
    n00b_panic("prefix.c: capacity overflow");
}

static inline size_t safe_mul_sz(size_t a, size_t b)
{
    size_t r;
    if (ckd_mul(&r, a, b)) prefix_capacity_overflow();
    return r;
}

static inline size_t safe_add_sz(size_t a, size_t b)
{
    size_t r;
    if (ckd_add(&r, a, b)) prefix_capacity_overflow();
    return r;
}

// Geometric grow for a `T data[]` with `len`/`cap` book-keeping.  Allocates
// a new buffer at the requested capacity, copies `old_len` elements, frees
// the old buffer.  Mirrors the `grow_buf` macro in algebra/nulls.c.
#define grow_buf(T, alloc, p_data, old_cap, old_len, new_cap)           \
    do {                                                                \
        size_t _gb_nc = (new_cap);                                      \
        T *_gb_new = n00b_alloc_array_with_opts(T, _gb_nc,              \
            &(n00b_alloc_opts_t){.allocator = (alloc)});                \
        if ((old_len) > 0 && *(p_data) != nullptr) {                    \
            memcpy(_gb_new, *(p_data),                                  \
                   safe_mul_sz((old_len), sizeof(T)));                  \
        }                                                               \
        if (*(p_data) != nullptr) {                                     \
            n00b_free(*(p_data));                                       \
        }                                                               \
        *(p_data) = _gb_new;                                            \
        (old_cap) = _gb_nc;                                             \
    } while (0)

// ===========================================================================
// TSetIdVec — caller-managed growable Vec<TSetId>.
// ===========================================================================

static inline void tset_id_vec_init(TSetIdVec *v) { *v = (TSetIdVec){}; }
static inline void tset_id_vec_clear(TSetIdVec *v) { v->len = 0; }

static void tset_id_vec_free(TSetIdVec *v)
{
    if (v->data) n00b_free(v->data);
    *v = (TSetIdVec){};
}

static void tset_id_vec_push(TSetIdVec *v, TSetId x, n00b_allocator_t *allocator)
{
    if (v->len == v->cap) {
        size_t nc = v->cap ? safe_mul_sz(v->cap, 2) : 8;
        grow_buf(TSetId, allocator, &v->data, v->cap, v->len, nc);
    }
    v->data[v->len++] = x;
}

// ===========================================================================
// ByteVec — caller-managed growable Vec<u8>.
// ===========================================================================

static inline void byte_vec_init(ByteVec *v) { *v = (ByteVec){}; }

static void byte_vec_free(ByteVec *v)
{
    if (v->data) n00b_free(v->data);
    *v = (ByteVec){};
}

// ===========================================================================
// VecDerTarget — caller-managed growable Vec<DerTarget> (declared in
// algebra.h; populated by `regex_builder_collect_der_targets`).
// ===========================================================================

static inline void target_vec_init(VecDerTarget *v) { *v = (VecDerTarget){}; }

static void target_vec_free(VecDerTarget *v)
{
    if (v->data) n00b_free(v->data);
    *v = (VecDerTarget){};
}

// ===========================================================================
// NodeIdArr — small linear-search "set" of NodeId.
//
// ORDER NOTE: every consumer in this file feeds the elements into a
// commutative reduction (`solver_or_id`, boolean any-nullable scan,
// idempotent set insert), so the substitution from BTreeSet's sorted
// iteration order to this unsorted array is sound.  Adding any caller
// that observes iteration order requires switching back to a sorted
// container.  Distinct from `NodeIdHashSet` below (used only by the
// AST DFS in `contains_lookahead_rel_max` where the frontier can grow
// large enough that linear scan becomes O(V^2)).
// ===========================================================================

typedef struct NodeIdArr {
    NodeId *data;
    size_t  len;
    size_t  cap;
} NodeIdArr;

static inline void nodeid_arr_init(NodeIdArr *s) { *s = (NodeIdArr){}; }

static void nodeid_arr_free(NodeIdArr *s)
{
    if (s->data) n00b_free(s->data);
    *s = (NodeIdArr){};
}

static bool nodeid_arr_contains(const NodeIdArr *s, NodeId n)
{
    for (size_t i = 0; i < s->len; ++i) {
        if (s->data[i].v == n.v) return true;
    }
    return false;
}

static bool nodeid_arr_insert(NodeIdArr *s, NodeId n, n00b_allocator_t *allocator)
{
    if (nodeid_arr_contains(s, n)) return false;
    if (s->len == s->cap) {
        size_t nc = s->cap ? safe_mul_sz(s->cap, 2) : 8;
        grow_buf(NodeId, allocator, &s->data, s->cap, s->len, nc);
    }
    s->data[s->len++] = n;
    return true;
}

static void nodeid_arr_clone(NodeIdArr *dst, const NodeIdArr *src,
                              n00b_allocator_t *allocator)
{
    dst->len = 0;
    if (dst->cap < src->len) {
        // Drop any old buffer and allocate one large enough.
        if (dst->data) n00b_free(dst->data);
        dst->data = n00b_alloc_array_with_opts(NodeId, src->len,
            &(n00b_alloc_opts_t){.allocator = allocator,
                                 .scan_kind = N00B_GC_SCAN_KIND_NONE});
        dst->cap  = src->len;
    }
    // Guard against memcpy(NULL, NULL, 0) on a fresh dst when src is empty —
    // strict reading of memcpy's contract requires valid pointers regardless
    // of n.
    if (src->len) {
        memcpy(dst->data, src->data, safe_mul_sz(src->len, sizeof(NodeId)));
    }
    dst->len = src->len;
}

// ===========================================================================
// NodeIdHashSet — n00b_dict_t(NodeId, bool) used by the AST DFS in
// `contains_lookahead_rel_max`.  NodeId is a 4-byte POD (uint32_t v) so
// `.skip_obj_hash = true` plus n00b_hash_raw drives content equality.
// Using a hash set keeps insert/contains expected O(1); the linear-scan
// NodeIdArr above would degrade to O(V^2) on adversarial alternation /
// concat sub-ASTs.
// ===========================================================================

typedef n00b_dict_t(NodeId, bool) NodeIdHashSet;

static NodeIdHashSet *nodeid_hashset_new(n00b_allocator_t *allocator)
{
    NodeIdHashSet *m = n00b_alloc_with_opts(
        NodeIdHashSet, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(m, .skip_obj_hash = true, .allocator = allocator,
                   .scan_kind = N00B_GC_SCAN_KIND_NONE);
    return m;
}

// Returns true iff the key was newly inserted.
static bool nodeid_hashset_insert(NodeIdHashSet *m, NodeId k)
{
    bool present;
    (void)n00b_dict_get(m, k, &present);
    if (present) return false;
    bool t = true;
    n00b_dict_put(m, k, t);
    return true;
}

// ===========================================================================
// NodeId scratch stack — local growable Vec<NodeId> with caller-managed
// (data, len, cap).  Single-owner, single-thread.
// ===========================================================================

static void nodeid_stack_push(NodeId **stack, size_t *len, size_t *cap, NodeId n,
                              n00b_allocator_t *allocator)
{
    if (*len == *cap) {
        size_t nc = *cap ? safe_mul_sz(*cap, 2) : 16;
        grow_buf(NodeId, allocator, stack, *cap, *len, nc);
    }
    (*stack)[(*len)++] = n;
}

static void nodeid_stack_free(NodeId **stack, size_t *len, size_t *cap)
{
    if (*stack) n00b_free(*stack);
    *stack = nullptr;
    *len = 0;
    *cap = 0;
}

// ===========================================================================
// File-private constants (mirroring upstream Rust `const` items).
// ===========================================================================

constexpr uint32_t WIDE_SET_BYTES            = 200u;
constexpr uint64_t TEDDY_MAX_FREQ_SUM        = 25000ull;
constexpr uint64_t TEDDY_WEAK_POSITION_FREQ  = 100000ull;
constexpr uint64_t TEDDY_MEMCHR_MAX_FREQ     = 2500ull;
constexpr uint64_t TEDDY_MEMCHR_MAX_FREQ_F   = 1500ull;
constexpr uint16_t RARE_BYTE_FREQ_LIMIT      = 25000u;
constexpr size_t   MAX_RANGE_SETS            = 3u;

// ===========================================================================
// calc_prefix_sets_inner
// ===========================================================================

n00b_result_t(TSetIdVec)
calc_prefix_sets_inner(RegexBuilder *self, NodeId start, bool strip_prefix)
{
    TSetIdVec out;
    tset_id_vec_init(&out);

    NodeId    node = start;
    NodeIdArr redundant;
    nodeid_arr_init(&redundant);
    nodeid_arr_insert(&redundant, NODE_ID_BOT, regex_builder_allocator(self));
    nodeid_arr_insert(&redundant, start, regex_builder_allocator(self));

    for (;;) {
        if (out.len != 0 && nodeid_arr_contains(&redundant, node)) break;
        if (regex_builder_any_nonbegin_nullable(self, node)) break;

        n00b_result_t(TRegexId) der = regex_builder_der(self, node, NULLABILITY_CENTER);
        if (!n00b_result_is_ok(der)) {
            n00b_err_t e = n00b_result_get_err(der);
            tset_id_vec_free(&out);
            nodeid_arr_free(&redundant);
            return n00b_result_err(TSetIdVec, e);
        }
        TRegexId der_tregex = n00b_result_get(der);

        VecDerTarget targets;
        target_vec_init(&targets);
        regex_builder_collect_der_targets(self, der_tregex, TSET_ID_FULL, &targets);

        TSetId full_union = TSET_ID_EMPTY;
        if (!strip_prefix) {
            for (size_t i = 0; i < targets.len; ++i) {
                if (targets.data[i].target.v != NODE_ID_BOT.v) {
                    full_union = solver_or_id(regex_builder_solver(self),
                                              full_union, targets.data[i].path);
                }
            }
        }

        // Filter `targets`, retaining only non-redundant entries.
        size_t w = 0;
        for (size_t i = 0; i < targets.len; ++i) {
            if (!nodeid_arr_contains(&redundant, targets.data[i].target)) {
                targets.data[w++] = targets.data[i];
            }
        }
        targets.len = w;

        if (targets.len == 0) {
            tset_id_vec_clear(&out);
            target_vec_free(&targets);
            break;
        }

        if (targets.len == 1) {
            NodeId target   = targets.data[0].target;
            TSetId char_set = targets.data[0].path;
            if (target.v == node.v) {
                tset_id_vec_clear(&out);
                target_vec_free(&targets);
                break;
            }
            TSetId set = (!strip_prefix && full_union.v != TSET_ID_EMPTY.v)
                       ? full_union
                       : char_set;
            tset_id_vec_push(&out, set, regex_builder_allocator(self));
            node = target;
            target_vec_free(&targets);
        }
        else {
            target_vec_free(&targets);
            break;
        }
    }

    nodeid_arr_free(&redundant);
    return n00b_result_ok(TSetIdVec, out);
}

// ===========================================================================
// calc_prefix_sets
// ===========================================================================

n00b_result_t(TSetIdVec)
calc_prefix_sets(RegexBuilder *self, NodeId rev_start)
{
    NodeId rs   = regex_builder_nonbegins(self, rev_start);
    NodeId safe = regex_builder_strip_prefix_safe(self, rs);
    return calc_prefix_sets_inner(self, safe, true);
}

// ===========================================================================
// calc_potential_start_prune
// ===========================================================================

n00b_result_t(TSetIdVec)
calc_potential_start_prune(RegexBuilder *self,
                           NodeId        node,
                           size_t        max_prefix_len,
                           size_t        max_frontier_size,
                           bool          exclude_initial)
{
    NodeId n  = regex_builder_prune_begin(self, node);
    NodeId n2 = regex_builder_strip_prefix_safe(self, n);
    return calc_potential_start(self, n2, max_prefix_len, max_frontier_size,
                                exclude_initial);
}

// ===========================================================================
// calc_potential_start
// ===========================================================================

n00b_result_t(TSetIdVec)
calc_potential_start(RegexBuilder *self,
                     NodeId        initial_node,
                     size_t        max_prefix_len,
                     size_t        max_frontier_size,
                     bool          exclude_initial)
{
    TSetIdVec out;
    tset_id_vec_init(&out);

    // ORDER NOTE: `nodes` and `next_nodes` were `BTreeSet<NodeId>` in
    // upstream Rust (sorted iteration).  This translation uses the
    // unsorted NodeIdArr because every consumer here is order-insensitive:
    // the commutative `solver_or_id` reduction into `union_set`, the
    // any-nullable scan, and the idempotent `nodeid_arr_insert` into
    // `next_nodes`.  Adding any caller that observes iteration order
    // requires switching back to a sorted container.
    NodeIdArr nodes;
    nodeid_arr_init(&nodes);
    nodeid_arr_insert(&nodes, initial_node, regex_builder_allocator(self));

    for (;;) {
        if (nodes.len == 0
            || nodes.len > max_frontier_size
            || out.len  >= max_prefix_len) break;

        bool any_null = false;
        for (size_t i = 0; i < nodes.len; ++i) {
            if (regex_builder_any_nonbegin_nullable(self, nodes.data[i])) {
                any_null = true;
                break;
            }
        }
        if (any_null) break;

        TSetId    union_set = TSET_ID_EMPTY;
        NodeIdArr next_nodes;
        nodeid_arr_init(&next_nodes);

        // Iterate over a snapshot of `nodes` (Rust did `&nodes.clone()`).
        NodeIdArr snapshot;
        nodeid_arr_init(&snapshot);
        nodeid_arr_clone(&snapshot, &nodes, regex_builder_allocator(self));

        bool       err_seen = false;
        n00b_err_t err_code = 0;
        for (size_t i = 0; i < snapshot.len; ++i) {
            NodeId cur = snapshot.data[i];
            n00b_result_t(TRegexId) der =
                regex_builder_der(self, cur, NULLABILITY_CENTER);
            if (!n00b_result_is_ok(der)) {
                err_seen = true;
                err_code = n00b_result_get_err(der);
                break;
            }
            TRegexId     der_tregex = n00b_result_get(der);
            VecDerTarget targets;
            target_vec_init(&targets);
            regex_builder_collect_der_targets(self, der_tregex, TSET_ID_FULL,
                                              &targets);
            for (size_t k = 0; k < targets.len; ++k) {
                NodeId t  = targets.data[k].target;
                TSetId cs = targets.data[k].path;
                if (exclude_initial && t.v == initial_node.v) continue;
                if (t.v == NODE_ID_BOT.v) continue;
                union_set = solver_or_id(regex_builder_solver(self),
                                         union_set, cs);
                nodeid_arr_insert(&next_nodes, t, regex_builder_allocator(self));
            }
            target_vec_free(&targets);
        }

        nodeid_arr_free(&snapshot);

        if (err_seen) {
            tset_id_vec_free(&out);
            nodeid_arr_free(&next_nodes);
            nodeid_arr_free(&nodes);
            return n00b_result_err(TSetIdVec, err_code);
        }

        if (next_nodes.len == 0 || union_set.v == TSET_ID_EMPTY.v) {
            if (next_nodes.len == 0) tset_id_vec_clear(&out);
            nodeid_arr_free(&next_nodes);
            break;
        }

        tset_id_vec_push(&out, union_set, regex_builder_allocator(self));
        nodeid_arr_free(&nodes);
        nodes = next_nodes;
    }

    nodeid_arr_free(&nodes);
    return n00b_result_ok(TSetIdVec, out);
}

// ===========================================================================
// collect_loop_factored_bodies / synthesize_inter_constraint /
// calc_combined_prefix
// ===========================================================================

// Returns true on success and populates *out (caller frees out->data).
// On non-loop-factored shape, returns false and leaves *out empty.
static bool collect_loop_factored_bodies(RegexBuilder *self, NodeId init,
                                         NodeIdArr *out)
{
    nodeid_arr_init(out);

    NodeId *stack = nullptr;
    size_t  s_len = 0;
    size_t  s_cap = 0;
    nodeid_stack_push(&stack, &s_len, &s_cap, init, regex_builder_allocator(self));

    bool ok = true;
    while (s_len > 0) {
        NodeId n = stack[--s_len];
        Kind   k = regex_builder_get_kind(self, n);
        if (k == KIND_INTER) {
            nodeid_stack_push(&stack, &s_len, &s_cap,
                              regex_builder_node_left(self, n),
                              regex_builder_allocator(self));
            nodeid_stack_push(&stack, &s_len, &s_cap,
                              regex_builder_node_right(self, n),
                              regex_builder_allocator(self));
        }
        else if (k == KIND_CONCAT
                 && regex_builder_node_left(self, n).v == NODE_ID_TS.v) {
            nodeid_arr_insert(out, regex_builder_node_right(self, n),
                              regex_builder_allocator(self));
        }
        else {
            ok = false;
            break;
        }
    }

    nodeid_stack_free(&stack, &s_len, &s_cap);
    if (!ok) {
        nodeid_arr_free(out);
        return false;
    }
    return true;
}

// Returns NODE_ID_MISSING if no constraint is synthesizable.
static NodeId synthesize_inter_constraint(RegexBuilder *self, NodeId init)
{
    if (regex_builder_get_kind(self, init) != KIND_INTER) {
        return NODE_ID_MISSING;
    }
    NodeIdArr bodies;
    if (!collect_loop_factored_bodies(self, init, &bodies)) {
        return NODE_ID_MISSING;
    }
    if (bodies.len == 0) {
        nodeid_arr_free(&bodies);
        return NODE_ID_MISSING;
    }
    NodeId out = regex_builder_mk_unions(self, bodies.data, bodies.len);
    nodeid_arr_free(&bodies);
    return out;
}

static n00b_result_t(TSetIdVec)
calc_combined_prefix(RegexBuilder *self,
                     NodeId        init,
                     size_t        fingerprint_depth,
                     size_t        max_prefix_len,
                     size_t        max_frontier_size)
{
    n00b_result_t(TSetIdVec) potential =
        calc_potential_start(self, init, max_prefix_len, max_frontier_size, true);
    if (!n00b_result_is_ok(potential)) return potential;
    TSetIdVec pot_vec = n00b_result_get(potential);

    NodeId    c = synthesize_inter_constraint(self, init);
    TSetIdVec head;
    tset_id_vec_init(&head);

    if (c.v != NODE_ID_MISSING.v) {
        NodeId constrained = regex_builder_mk_inter(self, init, c);
        n00b_result_t(TSetIdVec) h =
            calc_potential_start(self, constrained, fingerprint_depth,
                                 max_frontier_size, false);
        if (!n00b_result_is_ok(h)) {
            tset_id_vec_free(&pot_vec);
            return h;
        }
        head = n00b_result_get(h);
        if (head.len > fingerprint_depth) head.len = fingerprint_depth;
    }

    if (head.len == 0) {
        tset_id_vec_free(&head);
        return n00b_result_ok(TSetIdVec, pot_vec);
    }
    if (pot_vec.len < head.len) {
        tset_id_vec_free(&pot_vec);
        return n00b_result_ok(TSetIdVec, head);
    }

    Solver *sv = regex_builder_solver(self);
    for (size_t i = 0; i < head.len; ++i) {
        pot_vec.data[i] = solver_and_id(sv, pot_vec.data[i], head.data[i]);
    }
    tset_id_vec_free(&head);
    return n00b_result_ok(TSetIdVec, pot_vec);
}

// ===========================================================================
// strip_leading_lookbehind / contains_lookahead_rel_max
// ===========================================================================

static NodeId strip_leading_lookbehind(RegexBuilder *self, NodeId node)
{
    for (;;) {
        if (regex_builder_get_kind(self, node) != KIND_CONCAT) break;
        NodeId left = regex_builder_node_left(self, node);
        if (regex_builder_get_kind(self, left) != KIND_LOOKBEHIND) break;
        node = regex_builder_node_right(self, node);
    }
    return node;
}

static bool contains_lookahead_rel_max(RegexBuilder *self, NodeId start)
{
    NodeIdHashSet *visited = nodeid_hashset_new(regex_builder_allocator(self));
    NodeId        *stack   = nullptr;
    size_t         s_len   = 0;
    size_t         s_cap   = 0;
    nodeid_stack_push(&stack, &s_len, &s_cap, start, regex_builder_allocator(self));

    bool found = false;
    while (s_len > 0) {
        NodeId n = stack[--s_len];
        if (n.v == NODE_ID_MISSING.v) continue;
        if (!nodeid_hashset_insert(visited, n)) continue;

        Kind k = regex_builder_get_kind(self, n);
        if (k == KIND_LOOKAHEAD
            && regex_builder_get_extra(self, n) == UINT32_MAX) {
            found = true;
            break;
        }
        switch (k) {
        case KIND_PRED:
        case KIND_BEGIN:
        case KIND_END:
            break;
        case KIND_STAR:
        case KIND_COMPL:
            nodeid_stack_push(&stack, &s_len, &s_cap,
                              regex_builder_node_left(self, n),
                              regex_builder_allocator(self));
            break;
        default:
            nodeid_stack_push(&stack, &s_len, &s_cap,
                              regex_builder_node_left(self, n),
                              regex_builder_allocator(self));
            nodeid_stack_push(&stack, &s_len, &s_cap,
                              regex_builder_node_right(self, n),
                              regex_builder_allocator(self));
            break;
        }
    }

    nodeid_stack_free(&stack, &s_len, &s_cap);
    // `visited` is a GC-managed n00b_dict_t — no explicit free.
    return found;
}

// ===========================================================================
// classify_body_shape
// ===========================================================================

static NodeShape classify_body_shape(RegexBuilder    *self,
                                     NodeId           fwd_body,
                                     const TSetIdVec *fwd_potential)
{
    if (regex_builder_ends_with_ts(self, fwd_body)) return NODE_SHAPE_TRAILING_STAR;
    if (fwd_potential->len == 0)                    return NODE_SHAPE_BOUNDED;
    TSetId last = fwd_potential->data[fwd_potential->len - 1];
    if (solver_byte_count(regex_builder_solver(self), last) > WIDE_SET_BYTES) {
        return NODE_SHAPE_UNBOUNDED;
    }
    return NODE_SHAPE_BOUNDED;
}

// ===========================================================================
// Cost model
// ===========================================================================

static uint64_t scan_cost(RegexBuilder    *self,
                          const TSetIdVec *sets,
                          Direction        dir,
                          NodeShape        body_shape)
{
    if (sets->len == 0) return UINT64_MAX;

    uint64_t *freqs = n00b_alloc_array_with_opts(uint64_t, sets->len,
        &(n00b_alloc_opts_t){.allocator = regex_builder_allocator(self),
                             .scan_kind = N00B_GC_SCAN_KIND_NONE});
    for (size_t i = 0; i < sets->len; ++i) {
        uint8_t *bytes = nullptr;
        size_t   blen  = 0;
        solver_collect_bytes(regex_builder_solver(self), sets->data[i],
                             &bytes, &blen);
        uint64_t sum = 0;
        for (size_t j = 0; j < blen; ++j) {
            sum += (uint64_t)n00b_simd_BYTE_FREQ[bytes[j]];
        }
        freqs[i] = sum;
        // `bytes` is allocated by the n00b runtime (see solver.h doc) —
        // GC-managed, no explicit free.
    }

    size_t num_simd = sets->len < 3 ? sets->len : 3;
    if (num_simd == 0) {
        n00b_free(freqs);
        return UINT64_MAX;
    }

    double total     = (double)TOTAL_BYTE_FREQ;
    double best_prod = INFINITY;
    // Rust: for off in 0..=freqs.len() - num_simd
    for (size_t off = 0; off + num_simd <= sets->len; ++off) {
        double p = 1.0;
        for (size_t k = 0; k < num_simd; ++k) p *= (double)freqs[off + k];
        if (p < best_prod) best_prod = p;
    }
    n00b_free(freqs);

    double total_pow = 1.0;
    for (size_t k = 0; k < num_simd; ++k) total_pow *= total;
    double fire = best_prod / total_pow;

    double scan_per_byte;
    double verify_per_fire;
    if (dir == DIRECTION_REV) {
        scan_per_byte   = 0.5;
        verify_per_fire = 20.0;
    }
    else {
        scan_per_byte = 0.05;
        switch (body_shape) {
        case NODE_SHAPE_TRAILING_STAR: verify_per_fire =    1.0; break;
        case NODE_SHAPE_BOUNDED:       verify_per_fire =   50.0; break;
        case NODE_SHAPE_UNBOUNDED:     verify_per_fire = 5000.0; break;
        }
    }

    double cost = scan_per_byte + fire * verify_per_fire;
    return (uint64_t)(cost * 1e9);
}

static uint64_t cost_for(RegexBuilder    *self,
                         const TSetIdVec *sets,
                         Direction        dir,
                         NodeShape        body_shape)
{
    return scan_cost(self, sets, dir, body_shape);
}

// ===========================================================================
// rarest_freq / prefix_sets_rarity
// ===========================================================================

static uint64_t rarest_freq(RegexBuilder *self,
                            const TSetId *sets, size_t sets_len)
{
    uint64_t best = UINT64_MAX;
    bool     any  = false;
    for (size_t i = 0; i < sets_len; ++i) {
        uint8_t *bytes = nullptr;
        size_t   blen  = 0;
        solver_collect_bytes(regex_builder_solver(self), sets[i], &bytes, &blen);
        uint64_t sum = 0;
        for (size_t j = 0; j < blen; ++j) sum += (uint64_t)n00b_simd_BYTE_FREQ[bytes[j]];
        // `bytes` is GC-managed.
        if (!any || sum < best) {
            best = sum;
            any  = true;
        }
    }
    return any ? best : UINT64_MAX;
}

uint64_t prefix_sets_rarity(RegexBuilder *self,
                            const TSetId *sets, size_t sets_len)
{
    return rarest_freq(self, sets, sets_len);
}

// ===========================================================================
// PrefixSet helpers
// ===========================================================================

static inline void prefix_set_init(PrefixSet *p)
{
    tset_id_vec_init(&p->sets);
    p->cost = UINT64_MAX;
}

static inline void prefix_set_free(PrefixSet *p)
{
    tset_id_vec_free(&p->sets);
}

// ===========================================================================
// prefix_sets_compute_internal
// ===========================================================================

n00b_result_t(PrefixSets)
prefix_sets_compute_internal(RegexBuilder *self, NodeId node, NodeId rev_start)
{
    PrefixSets value;
    prefix_set_init(&value.fwd_potential);
    prefix_set_init(&value.fwd_potential_stripped);
    prefix_set_init(&value.rev_anchored);
    prefix_set_init(&value.rev_potential);

    NodeId fwd_body          = strip_leading_lookbehind(self, node);
    NodeId stripped_node     = regex_builder_strip_prefix_safe(self, node);
    NodeId fwd_body_stripped = strip_leading_lookbehind(self, stripped_node);

    n00b_result_t(TSetIdVec) fwd_pot =
        calc_potential_start(self, fwd_body, 16, 64, false);
    if (!n00b_result_is_ok(fwd_pot)) {
        return n00b_result_err(PrefixSets, n00b_result_get_err(fwd_pot));
    }
    TSetIdVec fwd_pot_v = n00b_result_get(fwd_pot);

    n00b_result_t(TSetIdVec) fwd_pot_str =
        calc_potential_start(self, fwd_body_stripped, 16, 64, false);
    if (!n00b_result_is_ok(fwd_pot_str)) {
        tset_id_vec_free(&fwd_pot_v);
        return n00b_result_err(PrefixSets, n00b_result_get_err(fwd_pot_str));
    }
    TSetIdVec fwd_pot_str_v = n00b_result_get(fwd_pot_str);

    n00b_result_t(TSetIdVec) rev_anc = calc_prefix_sets(self, rev_start);
    if (!n00b_result_is_ok(rev_anc)) {
        tset_id_vec_free(&fwd_pot_v);
        tset_id_vec_free(&fwd_pot_str_v);
        return n00b_result_err(PrefixSets, n00b_result_get_err(rev_anc));
    }
    TSetIdVec rev_anc_v = n00b_result_get(rev_anc);

    NodeId rev_combined_init;
    {
        NodeId n           = regex_builder_prune_begin(self, rev_start);
        rev_combined_init  = regex_builder_strip_prefix_safe(self, n);
    }
    n00b_result_t(TSetIdVec) rev_pot =
        calc_combined_prefix(self, rev_combined_init, 3, 16, 64);
    if (!n00b_result_is_ok(rev_pot)) {
        tset_id_vec_free(&fwd_pot_v);
        tset_id_vec_free(&fwd_pot_str_v);
        tset_id_vec_free(&rev_anc_v);
        return n00b_result_err(PrefixSets, n00b_result_get_err(rev_pot));
    }
    TSetIdVec rev_pot_v = n00b_result_get(rev_pot);

    if (rev_pot_v.len == 0) {
        // Optional rev fallback: strip_lb / reverse / strip_lb.  Rust's
        // `if let Ok(...)` drops the Err arm at each step; algebra here
        // returns n00b_result_t and the err side is just an int code, so
        // any failure on the first two steps simply means we skip the
        // step and continue with the empty `rev_pot`.  Only the final
        // calc_potential_start failure is propagated as a hard error.
        n00b_result_t(NodeId) body_r = regex_builder_strip_lb(self, node);
        if (n00b_result_is_ok(body_r)) {
            NodeId body = n00b_result_get(body_r);
            n00b_result_t(NodeId) body_rev_r =
                regex_builder_reverse(self, body);
            if (n00b_result_is_ok(body_rev_r)) {
                NodeId body_rev = n00b_result_get(body_rev_r);
                n00b_result_t(NodeId) bare_r =
                    regex_builder_strip_lb(self, body_rev);
                if (n00b_result_is_ok(bare_r)) {
                    NodeId bare = n00b_result_get(bare_r);
                    n00b_result_t(TSetIdVec) alt =
                        calc_potential_start(self, bare, 16, 64, false);
                    if (n00b_result_is_ok(alt)) {
                        tset_id_vec_free(&rev_pot_v);
                        rev_pot_v = n00b_result_get(alt);
                    }
                    else {
                        n00b_err_t e = n00b_result_get_err(alt);
                        tset_id_vec_free(&fwd_pot_v);
                        tset_id_vec_free(&fwd_pot_str_v);
                        tset_id_vec_free(&rev_anc_v);
                        tset_id_vec_free(&rev_pot_v);
                        return n00b_result_err(PrefixSets, e);
                    }
                }
            }
        }
    }

    NodeShape body_shape = classify_body_shape(self, fwd_body, &fwd_pot_v);

    value.fwd_potential.sets = fwd_pot_v;
    value.fwd_potential.cost =
        cost_for(self, &value.fwd_potential.sets, DIRECTION_FWD, body_shape);

    value.fwd_potential_stripped.sets = fwd_pot_str_v;
    value.fwd_potential_stripped.cost =
        cost_for(self, &value.fwd_potential_stripped.sets, DIRECTION_FWD,
                 body_shape);

    value.rev_anchored.sets = rev_anc_v;
    value.rev_anchored.cost =
        cost_for(self, &value.rev_anchored.sets, DIRECTION_REV, body_shape);

    value.rev_potential.sets = rev_pot_v;
    value.rev_potential.cost =
        cost_for(self, &value.rev_potential.sets, DIRECTION_REV, body_shape);

    return n00b_result_ok(PrefixSets, value);
}

// ===========================================================================
// build_strict_literal_prefix
// ===========================================================================

n00b_result_t(OptFwdPrefix)
build_strict_literal_prefix(RegexBuilder *self, NodeId node)
{
    OptFwdPrefix out = (OptFwdPrefix){.has_value = false, .value = nullptr};

    n00b_result_t(TSetIdVec) sets_r = calc_prefix_sets_inner(self, node, false);
    if (!n00b_result_is_ok(sets_r)) {
        return n00b_result_err(OptFwdPrefix, n00b_result_get_err(sets_r));
    }
    TSetIdVec sets = n00b_result_get(sets_r);

    if (sets.len == 0) {
        tset_id_vec_free(&sets);
        return n00b_result_ok(OptFwdPrefix, out);
    }

    // Collect bytes per set.  solver_collect_bytes returns the bytes via
    // (out_data, out_len) — the buffer is GC-managed; our local ByteVec
    // invariant requires cap == len.
    ByteVec *byte_sets = n00b_alloc_array_with_opts(ByteVec, sets.len,
        &(n00b_alloc_opts_t){.allocator = regex_builder_allocator(self)});
    bool     all_singletons = true;
    for (size_t i = 0; i < sets.len; ++i) {
        byte_vec_init(&byte_sets[i]);
        solver_collect_bytes(regex_builder_solver(self), sets.data[i],
                             &byte_sets[i].data, &byte_sets[i].len);
        byte_sets[i].cap = byte_sets[i].len;
        if (byte_sets[i].len != 1) all_singletons = false;
    }

    if (!all_singletons) {
        // byte_sets[i].data is GC-managed; we drop our wrapper only.
        n00b_free(byte_sets);
        tset_id_vec_free(&sets);
        return n00b_result_ok(OptFwdPrefix, out);
    }

    uint8_t *needle = n00b_alloc_array_with_opts(uint8_t, sets.len,
        &(n00b_alloc_opts_t){.allocator = regex_builder_allocator(self),
                              .scan_kind = N00B_GC_SCAN_KIND_NONE});
    for (size_t i = 0; i < sets.len; ++i) needle[i] = byte_sets[i].data[0];

    n00b_allocator_t *prev_alloc = n00b_set_current_allocator(
        regex_builder_allocator(self));
    FwdLiteralSearch *lit = n00b_simd_FwdLiteralSearch_new(needle, sets.len);
    n00b_restore_current_allocator(prev_alloc);
    n00b_free(needle);

    if (!lit) {
        n00b_free(byte_sets);
        tset_id_vec_free(&sets);
        return n00b_result_ok(OptFwdPrefix, out);
    }

    if ((uint16_t)n00b_simd_BYTE_FREQ[n00b_simd_FwdLiteralSearch_rare_byte(lit)] >= RARE_BYTE_FREQ_LIMIT) {
        // Free `lit` explicitly to match upstream Rust's `Drop` semantics —
        // `lit` owns SIMD tables that would otherwise accumulate per
        // pattern whose strict-literal prefix happens to use a common
        // rare byte.
        n00b_simd_FwdLiteralSearch_free(lit);
        n00b_free(byte_sets);
        tset_id_vec_free(&sets);
        return n00b_result_ok(OptFwdPrefix, out);
    }

    FwdPrefixSearch *search = fwd_prefix_search_new_literal(lit, regex_builder_allocator(self));
    if (!search) {
        n00b_simd_FwdLiteralSearch_free(lit);
        n00b_free(byte_sets);
        tset_id_vec_free(&sets);
        return n00b_result_ok(OptFwdPrefix, out);
    }

    out.has_value = true;
    out.value     = search;

    n00b_free(byte_sets);
    tset_id_vec_free(&sets);
    return n00b_result_ok(OptFwdPrefix, out);
}

// ===========================================================================
// try_build_fwd_range_prefix (helper, file-private)
// ===========================================================================

typedef struct ResultFwdRangePair {
    bool             has_search;
    FwdPrefixSearch *search;
} ResultFwdRangePair;

static ResultFwdRangePair try_build_fwd_range_prefix(const ByteVec *byte_sets_raw,
                                                     size_t         byte_sets_len,
                                                     size_t         anchor_pos,
                                                     n00b_allocator_t *allocator)
{
    ResultFwdRangePair r = (ResultFwdRangePair){.has_search = false,
                                                .search     = nullptr};

    const ByteVec *anchor_bytes = &byte_sets_raw[anchor_pos];
    uint32_t       freq_sum     = 0;
    for (size_t i = 0; i < anchor_bytes->len; ++i) {
        freq_sum += (uint32_t)n00b_simd_BYTE_FREQ[anchor_bytes->data[i]];
    }
    constexpr uint32_t RANGE_FREQ_THRESHOLD = 65535u;
    if (freq_sum >= RANGE_FREQ_THRESHOLD) return r;

    // tset_from_bytes returns TSet by value; solver_pp_collect_ranges
    // returns a ByteRangeSet by value, freed via ByteRangeSet_free.
    // ByteRange exposes `.start` / `.end`, so we splat into parallel
    // lo/hi arrays for the n00b_simd_FwdRangeSearch_new path.
    TSet         tset = tset_from_bytes(anchor_bytes->data, anchor_bytes->len);
    ByteRangeSet brs  = solver_pp_collect_ranges(&tset);

    if (brs.len == 0) {
        ByteRangeSet_free(&brs);
        return r;
    }

    uint8_t *lo = n00b_alloc_array_with_opts(uint8_t, brs.len,
        &(n00b_alloc_opts_t){.allocator = allocator,
                              .scan_kind = N00B_GC_SCAN_KIND_NONE});
    uint8_t *hi = n00b_alloc_array_with_opts(uint8_t, brs.len,
        &(n00b_alloc_opts_t){.allocator = allocator,
                              .scan_kind = N00B_GC_SCAN_KIND_NONE});
    for (size_t i = 0; i < brs.len; ++i) {
        lo[i] = brs.data[i].start;
        hi[i] = brs.data[i].end;
    }
    size_t rlen = brs.len;
    ByteRangeSet_free(&brs);

    uint8_t *use_lo      = lo;
    uint8_t *use_hi      = hi;
    size_t   use_len     = rlen;
    bool     used_coarse = false;
    uint8_t *coarse_lo   = nullptr;
    uint8_t *coarse_hi   = nullptr;

    if (rlen > MAX_RANGE_SETS) {
        // Coarsen by folding the high half.
        uint8_t *ascii_only = n00b_alloc_array_with_opts(uint8_t, anchor_bytes->len,
            &(n00b_alloc_opts_t){.allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_NONE});
        size_t   ascii_len  = 0;
        bool     has_high   = false;
        for (size_t i = 0; i < anchor_bytes->len; ++i) {
            uint8_t c = anchor_bytes->data[i];
            if (c < 0x80) ascii_only[ascii_len++] = c;
            else          has_high = true;
        }
        if (!has_high) {
            n00b_free(ascii_only);
            n00b_free(lo);
            n00b_free(hi);
            return r;
        }
        TSet ascii_tset = tset_from_bytes(ascii_only, ascii_len);
        n00b_free(ascii_only);

        ByteRangeSet ascii_brs = solver_pp_collect_ranges(&ascii_tset);
        size_t       clen      = ascii_brs.len;
        coarse_lo = n00b_alloc_array_with_opts(uint8_t, safe_add_sz(clen, 1),
            &(n00b_alloc_opts_t){.allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_NONE});
        coarse_hi = n00b_alloc_array_with_opts(uint8_t, safe_add_sz(clen, 1),
            &(n00b_alloc_opts_t){.allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_NONE});
        for (size_t i = 0; i < clen; ++i) {
            coarse_lo[i] = ascii_brs.data[i].start;
            coarse_hi[i] = ascii_brs.data[i].end;
        }
        ByteRangeSet_free(&ascii_brs);

        // Append high-byte fold.
        coarse_lo[clen] = 0x80;
        coarse_hi[clen] = 0xFF;
        ++clen;

        if (clen > MAX_RANGE_SETS) {
            n00b_free(coarse_lo);
            n00b_free(coarse_hi);
            n00b_free(lo);
            n00b_free(hi);
            return r;
        }
        use_lo      = coarse_lo;
        use_hi      = coarse_hi;
        use_len     = clen;
        used_coarse = true;
    }

    // Build all_sets covering the full byte_sets_raw window.
    TSet *all_sets = n00b_alloc_array(TSet, byte_sets_len);
    for (size_t i = 0; i < byte_sets_len; ++i) {
        all_sets[i] = tset_from_bytes(byte_sets_raw[i].data,
                                      byte_sets_raw[i].len);
    }

    // Allocate the FwdRangeSearch (and its internal ranges/sets arrays) in the
    // SAME per-regex arena as the FwdPrefixSearch wrapper below, so their
    // lifetimes match. Otherwise the search struct lands in the global GC heap
    // while its only live reference (FwdPrefixSearch.as.range) lives in the
    // arena — a cross-heap edge the collector doesn't keep alive, so a later
    // collection leaves as.range dangling (EXC_BAD_ACCESS in scan_fwd).
    n00b_allocator_t *prev_alloc = n00b_set_current_allocator(allocator);
    FwdRangeSearch   *rs         = n00b_simd_FwdRangeSearch_new(byte_sets_len,
                                                       anchor_pos,
                                                       use_lo, use_hi, use_len,
                                                       all_sets, byte_sets_len);
    n00b_restore_current_allocator(prev_alloc);
    FwdPrefixSearch *search = fwd_prefix_search_new_range(rs, allocator);
    if (search) {
        r.has_search = true;
        r.search     = search;
    }

    if (used_coarse) {
        n00b_free(coarse_lo);
        n00b_free(coarse_hi);
    }
    n00b_free(lo);
    n00b_free(hi);
    n00b_free(all_sets);
    return r;
}

// ===========================================================================
// try_build_fwd_search_raw
// ===========================================================================

static n00b_result_t(OptFwdPrefix)
try_build_fwd_search_raw(const ByteVec *byte_sets_raw, size_t byte_sets_len,
                         n00b_allocator_t *allocator)
{
    OptFwdPrefix r = (OptFwdPrefix){.has_value = false, .value = nullptr};

    size_t lit_len = 0;
    while (lit_len < byte_sets_len && byte_sets_raw[lit_len].len == 1) ++lit_len;

    if (lit_len >= 3) {
        uint8_t *needle = n00b_alloc_array_with_opts(uint8_t, lit_len,
            &(n00b_alloc_opts_t){.allocator = allocator,
                                  .scan_kind = N00B_GC_SCAN_KIND_NONE});
        for (size_t i = 0; i < lit_len; ++i) needle[i] = byte_sets_raw[i].data[0];
        n00b_allocator_t *prev_alloc = n00b_set_current_allocator(allocator);
        FwdLiteralSearch *lit = n00b_simd_FwdLiteralSearch_new(needle, lit_len);
        n00b_restore_current_allocator(prev_alloc);
        n00b_free(needle);

        if (!lit) {
            return n00b_result_ok(OptFwdPrefix, r);
        }

        if (lit_len == byte_sets_len
            || (uint16_t)n00b_simd_BYTE_FREQ[n00b_simd_FwdLiteralSearch_rare_byte(lit)]
                   < RARE_BYTE_FREQ_LIMIT) {
            FwdPrefixSearch *search = fwd_prefix_search_new_literal(lit, allocator);
            if (search) {
                r.has_value = true;
                r.value     = search;
            }
            else {
                n00b_simd_FwdLiteralSearch_free(lit);
            }
            return n00b_result_ok(OptFwdPrefix, r);
        }
        // Free `lit` explicitly to match upstream Rust's `Drop` semantics —
        // upstream does not silently leak the literal here.
        n00b_simd_FwdLiteralSearch_free(lit);
    }

    // Build (idx, freq) and filter f > 0.
    typedef struct FreqEnt { size_t i; uint64_t f; } FreqEnt;
    FreqEnt *freqs    = n00b_alloc_array_with_opts(FreqEnt, byte_sets_len,
        &(n00b_alloc_opts_t){.allocator = allocator,
                              .scan_kind = N00B_GC_SCAN_KIND_NONE});
    size_t   freqs_len = 0;
    for (size_t i = 0; i < byte_sets_len; ++i) {
        uint64_t sum = 0;
        for (size_t j = 0; j < byte_sets_raw[i].len; ++j) {
            sum += (uint64_t)n00b_simd_BYTE_FREQ[byte_sets_raw[i].data[j]];
        }
        if (sum > 0) {
            freqs[freqs_len].i = i;
            freqs[freqs_len].f = sum;
            ++freqs_len;
        }
    }
    if (freqs_len == 0) {
        n00b_free(freqs);
        return n00b_result_ok(OptFwdPrefix, r);
    }

    // Stable insertion sort ascending by freq (matches Rust's sort_by_key).
    for (size_t i = 1; i < freqs_len; ++i) {
        FreqEnt key = freqs[i];
        size_t  j   = i;
        while (j > 0 && freqs[j - 1].f > key.f) {
            freqs[j] = freqs[j - 1];
            --j;
        }
        freqs[j] = key;
    }

    size_t   rarest_idx       = freqs[0].i;
    uint64_t rarest_freq_sum  = freqs[0].f;
    size_t   rarest_len       = byte_sets_raw[rarest_idx].len;

    size_t narrow_positions = 0;
    for (size_t i = 0; i < byte_sets_len; ++i) {
        uint64_t sum = 0;
        for (size_t j = 0; j < byte_sets_raw[i].len; ++j) {
            sum += (uint64_t)n00b_simd_BYTE_FREQ[byte_sets_raw[i].data[j]];
        }
        if (sum <= TEDDY_WEAK_POSITION_FREQ) ++narrow_positions;
    }
    (void)narrow_positions;

    size_t non_full_positions = 0;
    for (size_t i = 0; i < byte_sets_len; ++i) {
        if (byte_sets_raw[i].len < 256) ++non_full_positions;
    }

    if (byte_sets_len > 1 && non_full_positions <= 1) {
        n00b_free(freqs);
        return n00b_result_ok(OptFwdPrefix, r);
    }

    bool degenerate = (byte_sets_len == 1);
    if (degenerate && rarest_freq_sum > TEDDY_MEMCHR_MAX_FREQ_F) {
        ResultFwdRangePair pr = try_build_fwd_range_prefix(byte_sets_raw,
                                                           byte_sets_len,
                                                           rarest_idx,
                                                           allocator);
        n00b_free(freqs);
        r.has_value = pr.has_search;
        r.value     = pr.search;
        return n00b_result_ok(OptFwdPrefix, r);
    }

    if (rarest_len > 16) {
        ResultFwdRangePair pr = try_build_fwd_range_prefix(byte_sets_raw,
                                                           byte_sets_len,
                                                           rarest_idx,
                                                           allocator);
        n00b_free(freqs);
        r.has_value = pr.has_search;
        r.value     = pr.search;
        return n00b_result_ok(OptFwdPrefix, r);
    }

    if (rarest_freq_sum > TEDDY_MAX_FREQ_SUM) {
        ResultFwdRangePair pr = try_build_fwd_range_prefix(byte_sets_raw,
                                                           byte_sets_len,
                                                           rarest_idx,
                                                           allocator);
        n00b_free(freqs);
        r.has_value = pr.has_search;
        r.value     = pr.search;
        return n00b_result_ok(OptFwdPrefix, r);
    }

    size_t *freq_order = n00b_alloc_array_with_opts(size_t, freqs_len,
        &(n00b_alloc_opts_t){.allocator = allocator,
                              .scan_kind = N00B_GC_SCAN_KIND_NONE});
    for (size_t i = 0; i < freqs_len; ++i) freq_order[i] = freqs[i].i;
    n00b_free(freqs);

    TSet *all_sets = n00b_alloc_array_with_opts(TSet, byte_sets_len,
        &(n00b_alloc_opts_t){.allocator = allocator,
                              .scan_kind = N00B_GC_SCAN_KIND_NONE});
    for (size_t i = 0; i < byte_sets_len; ++i) {
        all_sets[i] = tset_from_bytes(byte_sets_raw[i].data,
                                      byte_sets_raw[i].len);
    }
    n00b_allocator_t *prev_alloc = n00b_set_current_allocator(allocator);
    FwdPrefixSearchSimd *ps =
        n00b_simd_FwdPrefixSearch_new(byte_sets_len,
                                 freq_order, freqs_len,
                                 byte_sets_raw, byte_sets_len,
                                 all_sets, byte_sets_len);
    n00b_restore_current_allocator(prev_alloc);
    n00b_free(freq_order);
    n00b_free(all_sets);

    FwdPrefixSearch *search = fwd_prefix_search_new_prefix(ps, allocator);
    if (search) {
        r.has_value = true;
        r.value     = search;
    }
    return n00b_result_ok(OptFwdPrefix, r);
}

static n00b_result_t(OptFwdPrefix)
try_build_fwd_search(RegexBuilder *self, const TSetId *sets, size_t sets_len)
{
    ByteVec *byte_sets_raw = n00b_alloc_array(ByteVec, sets_len);
    for (size_t i = 0; i < sets_len; ++i) {
        byte_vec_init(&byte_sets_raw[i]);
        solver_collect_bytes(regex_builder_solver(self), sets[i],
                             &byte_sets_raw[i].data,
                             &byte_sets_raw[i].len);
        byte_sets_raw[i].cap = byte_sets_raw[i].len;
    }
    n00b_result_t(OptFwdPrefix) r = try_build_fwd_search_raw(byte_sets_raw,
                                                             sets_len,
                                                             regex_builder_allocator(self));
    // byte_sets_raw[i].data is GC-managed; only the wrapper array needs
    // an explicit drop.
    n00b_free(byte_sets_raw);
    return r;
}

// ===========================================================================
// build_fwd_prefix family
// ===========================================================================

static n00b_result_t(OptFwdPrefix)
build_fwd_prefix_from_sets(RegexBuilder *self, const TSetIdVec *full_sets)
{
    OptFwdPrefix r = (OptFwdPrefix){.has_value = false, .value = nullptr};
    if (full_sets->len > 0) {
        n00b_result_t(OptFwdPrefix) s = try_build_fwd_search(self,
                                                             full_sets->data,
                                                             full_sets->len);
        if (!n00b_result_is_ok(s)) return s;
        OptFwdPrefix sv = n00b_result_get(s);
        if (sv.has_value) {
            r.has_value = true;
            r.value     = sv.value;
        }
    }
    return n00b_result_ok(OptFwdPrefix, r);
}

static n00b_result_t(OptFwdPrefix)
build_fwd_prefix_simd(RegexBuilder *self, NodeId node)
{
    n00b_result_t(TSetIdVec) full =
        calc_potential_start(self, node, 16, 64, false);
    if (!n00b_result_is_ok(full)) {
        return n00b_result_err(OptFwdPrefix, n00b_result_get_err(full));
    }
    TSetIdVec full_v = n00b_result_get(full);
    n00b_result_t(OptFwdPrefix) r = build_fwd_prefix_from_sets(self, &full_v);
    tset_id_vec_free(&full_v);
    return r;
}

n00b_result_t(OptFwdPrefix)
build_fwd_prefix(RegexBuilder *self, NodeId node)
{
    OptFwdPrefix empty = (OptFwdPrefix){.has_value = false, .value = nullptr};
    if (!n00b_simd_has_simd()) return n00b_result_ok(OptFwdPrefix, empty);
    return build_fwd_prefix_simd(self, node);
}

// ===========================================================================
// build_rev_prefix_search
// ===========================================================================

RevTeddySearch *build_rev_prefix_search(RegexBuilder *self,
                                        const TSetId *sets, size_t sets_len)
{
    if (sets_len < 1) return nullptr;

    ByteVec *byte_sets_raw = n00b_alloc_array(ByteVec, sets_len);
    for (size_t i = 0; i < sets_len; ++i) {
        byte_vec_init(&byte_sets_raw[i]);
        solver_collect_bytes(regex_builder_solver(self), sets[i],
                             &byte_sets_raw[i].data,
                             &byte_sets_raw[i].len);
        byte_sets_raw[i].cap = byte_sets_raw[i].len;
    }

    size_t    num_simd = sets_len < 3 ? sets_len : 3;
    uint64_t *pos_freq = n00b_alloc_array(uint64_t, sets_len);
    for (size_t i = 0; i < sets_len; ++i) {
        uint64_t s = 0;
        for (size_t j = 0; j < byte_sets_raw[i].len; ++j) {
            s += (uint64_t)n00b_simd_BYTE_FREQ[byte_sets_raw[i].data[j]];
        }
        pos_freq[i] = s;
    }

    size_t      tail_offset = 0;
    // u128 not directly available in C; __uint128_t covers every supported arch.
    __uint128_t best_prod   = (__uint128_t)-1;
    for (size_t off = 0; off + num_simd <= sets_len; ++off) {
        __uint128_t prod = 1;
        for (size_t k = 0; k < num_simd; ++k) {
            prod *= (__uint128_t)pos_freq[off + k];
        }
        if (prod < best_prod) {
            best_prod   = prod;
            tail_offset = off;
        }
    }

    uint64_t rarest_freq_sum = UINT64_MAX;
    for (size_t k = 0; k < num_simd; ++k) {
        if (pos_freq[tail_offset + k] < rarest_freq_sum) {
            rarest_freq_sum = pos_freq[tail_offset + k];
        }
    }

    if (rarest_freq_sum > TEDDY_MAX_FREQ_SUM) {
        n00b_free(pos_freq);
        n00b_free(byte_sets_raw);
        return nullptr;
    }
    size_t narrow = 0;
    for (size_t k = 0; k < num_simd; ++k) {
        if (pos_freq[tail_offset + k] <= TEDDY_WEAK_POSITION_FREQ) ++narrow;
    }
    if (narrow < 2 && rarest_freq_sum > TEDDY_MEMCHR_MAX_FREQ) {
        n00b_free(pos_freq);
        n00b_free(byte_sets_raw);
        return nullptr;
    }

    __uint128_t combined_freq = 1;
    for (size_t k = 0; k < num_simd; ++k) {
        combined_freq *= (__uint128_t)pos_freq[tail_offset + k];
    }
    __uint128_t total_pow = 1;
    for (uint32_t k = 0; k < (uint32_t)num_simd; ++k) {
        total_pow *= (__uint128_t)TOTAL_BYTE_FREQ;
    }
    __uint128_t threshold = (__uint128_t)12 * total_pow / 256;
    if (combined_freq > threshold) {
        n00b_free(pos_freq);
        n00b_free(byte_sets_raw);
        return nullptr;
    }
    n00b_free(pos_freq);

    const ByteVec *window   = &byte_sets_raw[tail_offset];
    TSet          *all_sets = n00b_alloc_array(TSet, num_simd);
    for (size_t i = 0; i < num_simd; ++i) {
        all_sets[i] = tset_from_bytes(window[i].data, window[i].len);
    }

    n00b_allocator_t *prev_alloc = n00b_set_current_allocator(
        regex_builder_allocator(self));
    RevTeddySearch *out = n00b_simd_RevTeddySearch_new(num_simd, window, num_simd,
                                                  all_sets, num_simd, tail_offset);
    n00b_restore_current_allocator(prev_alloc);

    n00b_free(byte_sets_raw);
    n00b_free(all_sets);
    return out;
}

// ===========================================================================
// PrefixKind helpers
// ===========================================================================

bool prefix_kind_is_fwd(const PrefixKind *self)
{
    return self->tag == PREFIX_KIND_ANCHORED_FWD
        || self->tag == PREFIX_KIND_ANCHORED_FWD_LB;
}

bool prefix_kind_is_rev(const PrefixKind *self)
{
    return self->tag == PREFIX_KIND_ANCHORED_REV
        || self->tag == PREFIX_KIND_POTENTIAL_START;
}

PrefixKindTag prefix_kind_tag(const PrefixKind *self)        { return self->tag; }
FwdPrefixSearch *prefix_kind_fwd_search(const PrefixKind *self) { return self->fwd; }

[[maybe_unused]]
static const FwdPrefixSearch *PrefixKind_fwd_search_const(const PrefixKind *self)
{
    switch (self->tag) {
    case PREFIX_KIND_ANCHORED_FWD:
    case PREFIX_KIND_ANCHORED_FWD_LB:
        return self->fwd;
    default:
        return nullptr;
    }
}

// ===========================================================================
// try_rev_prefix
// ===========================================================================

n00b_result_t(OptPrefixRev)
try_rev_prefix(RegexBuilder *self, NodeId rev_node)
{
    OptPrefixRev out = (OptPrefixRev){.has_value = false,
                                      .kind      = (PrefixKind){},
                                      .search    = nullptr};

    if (regex_builder_get_nulls_id(self, rev_node).v != NULLS_ID_EMPTY.v) {
        return n00b_result_ok(OptPrefixRev, out);
    }

    n00b_result_t(TSetIdVec) anchored_r = calc_prefix_sets(self, rev_node);
    if (!n00b_result_is_ok(anchored_r)) {
        return n00b_result_err(OptPrefixRev, n00b_result_get_err(anchored_r));
    }
    TSetIdVec anchored = n00b_result_get(anchored_r);
    if (anchored.len > 0) {
        RevTeddySearch *s = build_rev_prefix_search(self, anchored.data,
                                                    anchored.len);
        if (s) {
            out.has_value = true;
            out.kind      = (PrefixKind){.tag = PREFIX_KIND_ANCHORED_REV,
                                         .fwd = nullptr};
            out.search    = s;
            tset_id_vec_free(&anchored);
            return n00b_result_ok(OptPrefixRev, out);
        }
    }
    tset_id_vec_free(&anchored);

    n00b_result_t(TSetIdVec) potential_r =
        calc_potential_start_prune(self, rev_node, 16, 64, true);
    if (!n00b_result_is_ok(potential_r)) {
        return n00b_result_err(OptPrefixRev, n00b_result_get_err(potential_r));
    }
    TSetIdVec potential = n00b_result_get(potential_r);
    if (potential.len > 0) {
        RevTeddySearch *s = build_rev_prefix_search(self, potential.data,
                                                    potential.len);
        if (s) {
            out.has_value = true;
            out.kind      = (PrefixKind){.tag = PREFIX_KIND_POTENTIAL_START,
                                         .fwd = nullptr};
            out.search    = s;
            tset_id_vec_free(&potential);
            return n00b_result_ok(OptPrefixRev, out);
        }
    }
    tset_id_vec_free(&potential);
    return n00b_result_ok(OptPrefixRev, out);
}

// ===========================================================================
// try_build_fwd_lb / body_absorbs_lb
// ===========================================================================

typedef struct ResultBool { bool value; } ResultBool;

static n00b_result_t(ResultBool)
body_absorbs_lb(RegexBuilder *self, NodeId body, NodeId lb)
{
    ResultBool out = (ResultBool){.value = false};

    n00b_result_t(TSetIdVec) body_first_r =
        calc_potential_start(self, body, 1, 64, false);
    if (!n00b_result_is_ok(body_first_r)) {
        return n00b_result_err(ResultBool, n00b_result_get_err(body_first_r));
    }
    TSetIdVec body_first = n00b_result_get(body_first_r);

    n00b_result_t(TSetIdVec) lb_first_r =
        calc_potential_start(self, lb, 1, 64, false);
    if (!n00b_result_is_ok(lb_first_r)) {
        tset_id_vec_free(&body_first);
        return n00b_result_err(ResultBool, n00b_result_get_err(lb_first_r));
    }
    TSetIdVec lb_first = n00b_result_get(lb_first_r);

    if (body_first.len == 0 || lb_first.len == 0) {
        tset_id_vec_free(&body_first);
        tset_id_vec_free(&lb_first);
        return n00b_result_ok(ResultBool, out);
    }
    TSetId bf = body_first.data[0];
    TSetId lf = lb_first.data[0];

    uint8_t *body_bytes = nullptr;
    size_t   body_len   = 0;
    solver_collect_bytes(regex_builder_solver(self), bf, &body_bytes, &body_len);
    uint8_t *lb_bytes   = nullptr;
    size_t   lb_len     = 0;
    solver_collect_bytes(regex_builder_solver(self), lf, &lb_bytes, &lb_len);

    bool result = false;
    if (body_len >= 64) {
        bool present[256] = {};
        for (size_t i = 0; i < body_len; ++i) present[body_bytes[i]] = true;
        result = true;
        for (size_t i = 0; i < lb_len; ++i) {
            if (!present[lb_bytes[i]]) {
                result = false;
                break;
            }
        }
    }
    out.value = result;

    // body_bytes / lb_bytes are GC-managed.
    tset_id_vec_free(&body_first);
    tset_id_vec_free(&lb_first);
    return n00b_result_ok(ResultBool, out);
}

static n00b_result_t(OptFwdPrefix)
try_build_fwd_lb(RegexBuilder *self, NodeId node)
{
    OptFwdPrefix out = (OptFwdPrefix){.has_value = false, .value = nullptr};

    NodeId body = strip_leading_lookbehind(self, node);
    if (body.v == node.v
        || regex_builder_node_right(self, node).v != body.v) {
        return n00b_result_ok(OptFwdPrefix, out);
    }
    NodeId lb = regex_builder_node_left(self, node);
    if (regex_builder_get_kind(self, lb) != KIND_LOOKBEHIND) {
        return n00b_result_ok(OptFwdPrefix, out);
    }

    NodeId lb_inner    = regex_builder_get_lookbehind_inner(self, lb);
    NodeId lb_stripped = regex_builder_nonbegins(self, lb_inner);
    for (;;) {
        NodeId stripped = regex_builder_strip_prefix_safe(self, lb_stripped);
        NodeId after    = regex_builder_nonbegins(self, stripped);
        if (after.v == lb_stripped.v) break;
        lb_stripped = after;
    }
    uint32_t fl = 0;
    if (!regex_builder_get_fixed_length(self, lb_stripped, &fl)) {
        return n00b_result_ok(OptFwdPrefix, out);
    }
    if (fl < 1 || fl > 64) return n00b_result_ok(OptFwdPrefix, out);

    n00b_result_t(ResultBool) absorbs_r = body_absorbs_lb(self, body, lb_stripped);
    if (!n00b_result_is_ok(absorbs_r)) {
        return n00b_result_err(OptFwdPrefix, n00b_result_get_err(absorbs_r));
    }
    if (n00b_result_get(absorbs_r).value) {
        return n00b_result_ok(OptFwdPrefix, out);
    }

    NodeId lb_body = regex_builder_mk_concat(self, lb_stripped, body);
    n00b_result_t(OptFwdPrefix) pp = build_fwd_prefix(self, lb_body);
    if (!n00b_result_is_ok(pp)) return pp;
    OptFwdPrefix pv = n00b_result_get(pp);
    out.has_value = pv.has_value;
    out.value     = pv.value;
    return n00b_result_ok(OptFwdPrefix, out);
}

// ===========================================================================
// select_prefix / select_prefix_simd
// ===========================================================================

// Try to fill `out` with a rev-prefix kind+skip from `ps`.  Replaces the
// upstream GNU statement-expression macro: a static helper makes the
// ownership flow visible at the call site.
static bool try_rev_fill(PrefixSelect           *out,
                         RegexBuilder           *self,
                         const PrefixSets       *ps,
                         bool                    rev_usable)
{
    if (!rev_usable) return false;

    if (ps->rev_anchored.sets.len > 0) {
        RevTeddySearch *s = build_rev_prefix_search(self,
                                                    ps->rev_anchored.sets.data,
                                                    ps->rev_anchored.sets.len);
        if (s) {
            out->has_kind = true;
            out->kind     = (PrefixKind){.tag = PREFIX_KIND_ANCHORED_REV,
                                         .fwd = nullptr};
            out->has_skip = true;
            out->skip     = s;
            return true;
        }
    }

    if (ps->rev_potential.sets.len > 0) {
        RevTeddySearch *s = build_rev_prefix_search(self,
                                                    ps->rev_potential.sets.data,
                                                    ps->rev_potential.sets.len);
        if (s) {
            out->has_kind = true;
            out->kind     = (PrefixKind){.tag = PREFIX_KIND_POTENTIAL_START,
                                         .fwd = nullptr};
            out->has_skip = true;
            out->skip     = s;
            return true;
        }
    }

    return false;
}

static n00b_result_t(PrefixSelect)
select_prefix_simd(RegexBuilder *self,
                   NodeId        node,
                   NodeId        rev_start,
                   bool          has_look,
                   uint32_t      min_len,
                   bool          no_fwd_prefix)
{
    PrefixSelect out = (PrefixSelect){.has_kind = false,
                                      .kind     = (PrefixKind){},
                                      .has_skip = false,
                                      .skip     = nullptr};

    if (min_len == 0) {
        if (!no_fwd_prefix && has_look
            && regex_builder_contains_lookbehind(node, self)) {
            n00b_result_t(OptFwdPrefix) fp = try_build_fwd_lb(self, node);
            if (!n00b_result_is_ok(fp)) {
                return n00b_result_err(PrefixSelect, n00b_result_get_err(fp));
            }
            OptFwdPrefix fv = n00b_result_get(fp);
            if (fv.has_value) {
                out.has_kind = true;
                out.kind     = (PrefixKind){.tag = PREFIX_KIND_ANCHORED_FWD_LB,
                                            .fwd = fv.value};
                return n00b_result_ok(PrefixSelect, out);
            }
        }

        n00b_result_t(PrefixSets) ps_r =
            prefix_sets_compute_internal(self, node, rev_start);
        if (n00b_result_is_err(ps_r)) {
            return n00b_result_err(PrefixSelect, n00b_result_get_err(ps_r));
        }
        PrefixSets ps = n00b_result_get(ps_r);
        bool rev_usable =
            regex_builder_get_nulls_id(self, rev_start).v == NULLS_ID_EMPTY.v
            && (ps.rev_anchored.sets.len > 0
                || ps.rev_potential.sets.len > 0);
        bool filled = try_rev_fill(&out, self, &ps, rev_usable);
        prefix_set_free(&ps.fwd_potential);
        prefix_set_free(&ps.fwd_potential_stripped);
        prefix_set_free(&ps.rev_anchored);
        prefix_set_free(&ps.rev_potential);
        if (filled) {
            return n00b_result_ok(PrefixSelect, out);
        }
        return n00b_result_ok(PrefixSelect, out);
    }

    n00b_result_t(PrefixSets) ps_r =
        prefix_sets_compute_internal(self, node, rev_start);
    if (!n00b_result_is_ok(ps_r)) {
        return n00b_result_err(PrefixSelect, n00b_result_get_err(ps_r));
    }
    PrefixSets ps = n00b_result_get(ps_r);

    uint64_t fwd_cost =
        ps.fwd_potential.cost < ps.fwd_potential_stripped.cost
            ? ps.fwd_potential.cost
            : ps.fwd_potential_stripped.cost;
    uint64_t rev_cost =
        ps.rev_anchored.cost < ps.rev_potential.cost
            ? ps.rev_anchored.cost
            : ps.rev_potential.cost;
    bool rev_usable =
        regex_builder_get_nulls_id(self, rev_start).v == NULLS_ID_EMPTY.v
        && (ps.rev_anchored.sets.len > 0
            || ps.rev_potential.sets.len > 0);
    bool fwd_wins = fwd_cost < rev_cost;

    bool       fwd_have      = false;
    PrefixKind fwd_candidate = (PrefixKind){};

    if (no_fwd_prefix) {
        // Leave fwd_have = false.
    }
    else if (has_look && regex_builder_contains_lookbehind(node, self)) {
        n00b_result_t(OptFwdPrefix) fp = try_build_fwd_lb(self, node);
        if (!n00b_result_is_ok(fp)) {
            n00b_err_t e = n00b_result_get_err(fp);
            prefix_set_free(&ps.fwd_potential);
            prefix_set_free(&ps.fwd_potential_stripped);
            prefix_set_free(&ps.rev_anchored);
            prefix_set_free(&ps.rev_potential);
            return n00b_result_err(PrefixSelect, e);
        }
        OptFwdPrefix fv = n00b_result_get(fp);
        if (fv.has_value) {
            fwd_have      = true;
            fwd_candidate = (PrefixKind){.tag = PREFIX_KIND_ANCHORED_FWD_LB,
                                         .fwd = fv.value};
        }
    }
    else if (has_look && contains_lookahead_rel_max(self, node)) {
        // Leave fwd_have = false.
    }
    else {
        n00b_result_t(OptFwdPrefix) fp =
            build_fwd_prefix_from_sets(self, &ps.fwd_potential.sets);
        if (!n00b_result_is_ok(fp)) {
            n00b_err_t e = n00b_result_get_err(fp);
            prefix_set_free(&ps.fwd_potential);
            prefix_set_free(&ps.fwd_potential_stripped);
            prefix_set_free(&ps.rev_anchored);
            prefix_set_free(&ps.rev_potential);
            return n00b_result_err(PrefixSelect, e);
        }
        OptFwdPrefix fv = n00b_result_get(fp);
        if (fv.has_value) {
            fwd_have      = true;
            fwd_candidate = (PrefixKind){.tag = PREFIX_KIND_ANCHORED_FWD,
                                         .fwd = fv.value};
        }
        else if (regex_builder_is_infinite(self, node)) {
            n00b_result_t(OptFwdPrefix) lit =
                build_strict_literal_prefix(self, node);
            if (!n00b_result_is_ok(lit)) {
                n00b_err_t e = n00b_result_get_err(lit);
                prefix_set_free(&ps.fwd_potential);
                prefix_set_free(&ps.fwd_potential_stripped);
                prefix_set_free(&ps.rev_anchored);
                prefix_set_free(&ps.rev_potential);
                return n00b_result_err(PrefixSelect, e);
            }
            OptFwdPrefix lv = n00b_result_get(lit);
            if (lv.has_value) {
                fwd_have      = true;
                fwd_candidate = (PrefixKind){.tag = PREFIX_KIND_ANCHORED_FWD,
                                             .fwd = lv.value};
            }
        }
    }

    if (fwd_wins && !no_fwd_prefix && fwd_have) {
        out.has_kind = true;
        out.kind     = fwd_candidate;
        prefix_set_free(&ps.fwd_potential);
        prefix_set_free(&ps.fwd_potential_stripped);
        prefix_set_free(&ps.rev_anchored);
        prefix_set_free(&ps.rev_potential);
        return n00b_result_ok(PrefixSelect, out);
    }
    if (try_rev_fill(&out, self, &ps, rev_usable)) {
        // Rev path won; `fwd_candidate.fwd` (if any) was already built and
        // owns SIMD tables / TSets / byte vectors.  Upstream Rust's RAII
        // drops it; in C we must free it explicitly or it leaks per regex
        // build that takes this branch.
        if (fwd_have && fwd_candidate.fwd) {
            fwd_prefix_search_free(fwd_candidate.fwd);
        }
        prefix_set_free(&ps.fwd_potential);
        prefix_set_free(&ps.fwd_potential_stripped);
        prefix_set_free(&ps.rev_anchored);
        prefix_set_free(&ps.rev_potential);
        return n00b_result_ok(PrefixSelect, out);
    }
    if (fwd_have) {
        out.has_kind = true;
        out.kind     = fwd_candidate;
    }
    prefix_set_free(&ps.fwd_potential);
    prefix_set_free(&ps.fwd_potential_stripped);
    prefix_set_free(&ps.rev_anchored);
    prefix_set_free(&ps.rev_potential);
    return n00b_result_ok(PrefixSelect, out);
}

n00b_result_t(PrefixSelect)
select_prefix(RegexBuilder *self,
              NodeId        node,
              NodeId        rev_start,
              bool          has_look,
              uint32_t      min_len,
              size_t        max_cap,
              bool          no_fwd_prefix)
{
    (void)max_cap;     // only used under upstream `feature = "convergence_prefix"`.
    return select_prefix_simd(self, node, rev_start, has_look, min_len,
                              no_fwd_prefix);
    // NOTE: the upstream `convergence_prefix` cargo-feature path is
    // omitted (gated `#[cfg(feature = "convergence_prefix")]` in Rust).
    // This is a per-file translation, so the feature-gated branch is
    // dropped; a future workstream can re-introduce it if the n00b build
    // wants to support it.
}

// ===========================================================================
// Engine.c-facing aliases (mirror upstream phase-2 translator-invented
// names — kept for ABI parity with the engine TU that has not yet been
// ported).
// ===========================================================================

const uint32_t prefix_SKIP_FREQ_THRESHOLD = SKIP_FREQ_THRESHOLD;

n00b_result_t(TSetIdVec)
prefix_calc_potential_start(RegexBuilder *self,
                            NodeId        initial_node,
                            size_t        max_prefix_len,
                            size_t        max_frontier_size,
                            bool          exclude_initial)
{
    return calc_potential_start(self, initial_node, max_prefix_len,
                                max_frontier_size, exclude_initial);
}

n00b_result_t(TSetIdVec)
prefix_calc_prefix_sets_inner(RegexBuilder *self, NodeId start,
                              bool strip_prefix)
{
    return calc_prefix_sets_inner(self, start, strip_prefix);
}

void prefix_kind_free(PrefixKind *self)
{
    if (!self) return;
    // self->fwd is borrowed-vs-owned per builder semantics; this disposer
    // frees only the wrapper.
    n00b_free(self);
}

void prefix_rev_skip_free(void *rev_skip)
{
    // RevTeddySearch is owned by the LDFA via OptionRevTeddySearch when
    // ownership transfers; otherwise free here.
    if (rev_skip) n00b_free(rev_skip);
}

// The internal select_prefix() pipes algebra-layer errors (n00b_regex_
// algebra_err_t values) through n00b_result_t(PrefixSelect).err.  But the
// caller (from_node_inner in regex.c) treats the returned int as a
// n00b_regex_engine_err_t — different enum, different value space.
// Translate at the boundary, same mapping table as stream.c.
static inline n00b_regex_engine_err_t algebra_err_to_engine(int e)
{
    switch ((n00b_regex_algebra_err_t)e) {
    case N00B_REGEX_ALGEBRA_ERR_NONE:                  return N00B_REGEX_ENGINE_ERR_NONE;
    case N00B_REGEX_ALGEBRA_ERR_ANCHOR_LIMIT:          return N00B_REGEX_ENGINE_ERR_UNSUPPORTED_PATTERN;
    case N00B_REGEX_ALGEBRA_ERR_STATE_SPACE_EXPLOSION: return N00B_REGEX_ENGINE_ERR_CAPACITY_EXCEEDED;
    case N00B_REGEX_ALGEBRA_ERR_UNSUPPORTED_PATTERN:   return N00B_REGEX_ENGINE_ERR_UNSUPPORTED_PATTERN;
    }
    return N00B_REGEX_ENGINE_ERR_ALGEBRA;
}

void *prefix_select_prefix(RegexBuilder *self,
                           NodeId        node,
                           NodeId        ts_rev_start,
                           bool          has_look,
                           uint32_t      min_len,
                           size_t        max_cap,
                           bool          no_fwd_prefix,
                           PrefixSelect *out)
{
    n00b_result_t(PrefixSelect) r = select_prefix(self, node, ts_rev_start,
                                                  has_look, min_len, max_cap,
                                                  no_fwd_prefix);
    if (!n00b_result_is_ok(r)) {
        out->has_kind = false;
        out->has_skip = false;
        out->skip     = nullptr;
        // Hand the caller a heap-allocated err code.  Caller frees with
        // `n00b_free` after consuming.  The internal err is algebra-layer;
        // translate to engine-layer for the caller (from_node_inner).
        int *err = n00b_alloc(int);
        *err     = (int)algebra_err_to_engine((int)n00b_result_get_err(r));
        return err;
    }
    *out = n00b_result_get(r);
    return nullptr;
}

// ===========================================================================
// Test-facing public API: heap-allocated PrefixSets + accessors.
//
// `prefix_sets_compute` returns nullptr on error and writes the err code
// to `*err_out` (when non-nullptr).  On success returns a heap PrefixSets
// the caller releases with `prefix_sets_free`.  The three accessors copy
// the underlying TSetIdVec into a freshly allocated buffer so the caller
// may release the result with `n00b_free`.
// ===========================================================================

PrefixSets *prefix_sets_compute(RegexBuilder *self, NodeId node, NodeId rev_start,
                                int *err_out)
{
    n00b_result_t(PrefixSets) r =
        prefix_sets_compute_internal(self, node, rev_start);
    if (!n00b_result_is_ok(r)) {
        if (err_out != nullptr) *err_out = (int)n00b_result_get_err(r);
        return nullptr;
    }
    PrefixSets *p = n00b_alloc(PrefixSets);
    *p = n00b_result_get(r);
    if (err_out != nullptr) *err_out = 0;
    return p;
}

void prefix_sets_free(PrefixSets *self)
{
    if (self == nullptr) return;
    tset_id_vec_free(&self->fwd_potential.sets);
    tset_id_vec_free(&self->fwd_potential_stripped.sets);
    tset_id_vec_free(&self->rev_anchored.sets);
    tset_id_vec_free(&self->rev_potential.sets);
    n00b_free(self);
}

// Accessors hand out an owned copy of the TSetId array so callers may free
// it with `n00b_free`.  The PrefixSets retains its own copy for subsequent
// accessor calls and final teardown.
static void copy_tset_id_vec(const TSetIdVec *v, TSetId **out, size_t *out_len)
{
    *out_len = v->len;
    if (v->len == 0) {
        *out = nullptr;
        return;
    }
    TSetId *buf = n00b_alloc_array(TSetId, v->len);
    memcpy(buf, v->data, safe_mul_sz(v->len, sizeof(TSetId)));
    *out = buf;
}

void prefix_sets_rev_anchored(const PrefixSets *self, TSetId **out, size_t *out_len)
{
    copy_tset_id_vec(&self->rev_anchored.sets, out, out_len);
}

void prefix_sets_rev_potential(const PrefixSets *self, TSetId **out, size_t *out_len)
{
    copy_tset_id_vec(&self->rev_potential.sets, out, out_len);
}

void prefix_sets_fwd_potential(const PrefixSets *self, TSetId **out, size_t *out_len)
{
    copy_tset_id_vec(&self->fwd_potential.sets, out, out_len);
}
