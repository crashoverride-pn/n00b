/*
 * src/text/regex/engine/regex.c
 *
 * Faithful per-file translation of resharp-c's `src/engine/regex.c`
 * (which is itself the C port of upstream Rust `resharp::Regex`), with
 * primitives migrated to n00b idioms:
 *
 *   - allocation: the upstream C port's x-prefixed alloc shims become
 *     n00b_alloc(T) / n00b_alloc_array(T, N) / n00b_free.
 *   - vectors:   resharp's MatchVec/UsizeVec and the file-local edge / scc /
 *     queue helpers -> typed n00b_list_t(T) * (private — single-owner, no
 *     rwlock).
 *   - hashmaps:  NodeUSizeMap -> n00b_dict_t(NodeId, size_t).
 *   - mutex:     resharp's Mutex<RegexInner> (a wrapper around a spinlock +
 *     opaque inner pointer in the C port) -> n00b_mutex_t embedded in Regex
 *     plus RegexInner *inner.
 *   - atomics:   _Atomic(bool) once-flags accessed via n00b_atomic_* macros.
 *   - errors:    Error* chains -> n00b_regex_engine_err_t errno-style;
 *     regex_builder_* algebra fallibles use n00b_result_t(...).
 *   - assertions: the upstream C macro family (always-on require, formatted
 *     panic, unreachable marker) translates to n00b_require / n00b_panic /
 *     n00b_unreachable.
 *   - byte ops:  memcpy / memset direct (D13).
 */

#include "n00b.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdckdint.h>
#include <stdatomic.h>
#include <string.h> // memcpy / memset (D13)

#include "core/alloc.h"
#include "core/thread.h" // for n00b_thread_id used by core/lock_common.h
#include "core/mutex.h"
#include "core/atomic.h"

#include "adt/list.h"
#include "adt/option.h"
#include "adt/result.h"
#include "adt/dict.h"

#include "util/assert.h"
#include "util/panic.h"

#include "internal/regex/regex.h"
#include "internal/regex/algebra.h"
#include "internal/regex/nulls.h"
#include "internal/regex/solver.h"
#include "internal/regex/accel.h"
#include "internal/regex/engine.h"
#include "internal/regex/bdfa.h"
#include "internal/regex/prefix.h"
#include "internal/regex/fas.h"
#include "internal/regex/parser.h"

// Sibling-engine helper declarations live in the internal regex headers
// (engine.h / fas.h / bdfa.h / prefix.h / accel.h / parser.h) — included
// above.  This TU pulls them in directly rather than re-declaring local
// externs, so signature drift between regex.c and the engine TUs is
// caught at compile time.

// ---------------------------------------------------------------------------
// Local checked-arithmetic helpers (size_t flavor).  Translation of
// resharp-c's `common/ckd.h` per § 7.5: use `<stdckdint.h>` directly,
// route overflow to `n00b_panic` (D9).
// ---------------------------------------------------------------------------

[[noreturn]] static inline void regex_capacity_overflow(const char *where)
{
    n00b_panic("engine/regex.c: capacity overflow in «#»",
               n00b_string_from_cstr(where));
}

static inline size_t ckd_mul_sz_or_panic(size_t a, size_t b, const char *where)
{
    size_t out;
    if (ckd_mul(&out, a, b)) regex_capacity_overflow(where);
    return out;
}

// ---------------------------------------------------------------------------
// PatternFlags layout-aliasing.  The parser entry point casts a
// `const PatternFlags *` straight into the parser's internal shape; field
// order MUST match `internal/regex/parser.h::PatternFlags`.  Translated
// directly here (in addition to `parser.h` declaring the type) to keep the
// invariant local to this TU when a future field-reordering happens.
// ---------------------------------------------------------------------------

typedef struct PatternFlagsLayout {
    bool     unicode;
    bool     full_unicode;
    bool     case_insensitive;
    bool     dot_matches_new_line;
    bool     multiline;
    bool     ignore_whitespace;
    bool     ascii_perl_classes;
    uint64_t expanded_ast_limit;
    size_t   max_list_len;
} PatternFlagsLayout;

// ---------------------------------------------------------------------------
// has_simd / escape re-exports
// ---------------------------------------------------------------------------

bool  has_simd(void) { return n00b_simd_has_simd(); }

char *resharp_escape(const char *text) { return parser_escape(text); }

void  resharp_escape_into(const char *text, char **out_buf, size_t *out_len,
                          size_t *out_cap)
{
    parser_escape_into(text, out_buf, out_len, out_cap);
}

// ---------------------------------------------------------------------------
// RegexOptions
// ---------------------------------------------------------------------------

RegexOptions regex_options_default(void)
{
    return (RegexOptions){
        .max_dfa_capacity      = (size_t)UINT16_MAX,
        .lookahead_context_max = 800,
        .unicode               = UNICODE_MODE_DEFAULT,
        .case_insensitive      = false,
        .dot_matches_new_line  = false,
        .multiline             = true,
        .ignore_whitespace     = false,
        .hardened              = false,
        .unbounded_size        = false,
    };
}

RegexOptions regex_options_unicode(RegexOptions self, UnicodeMode mode) {
    self.unicode = mode; return self;
}
RegexOptions regex_options_case_insensitive(RegexOptions self, bool yes) {
    self.case_insensitive = yes; return self;
}
RegexOptions regex_options_dot_matches_new_line(RegexOptions self, bool yes) {
    self.dot_matches_new_line = yes; return self;
}
RegexOptions regex_options_multiline(RegexOptions self, bool yes) {
    self.multiline = yes; return self;
}
RegexOptions regex_options_ignore_whitespace(RegexOptions self, bool yes) {
    self.ignore_whitespace = yes; return self;
}
RegexOptions regex_options_hardened(RegexOptions self, bool yes) {
    self.hardened = yes; return self;
}
RegexOptions regex_options_unbounded_size(RegexOptions self, bool yes) {
    self.unbounded_size = yes; return self;
}

// ---------------------------------------------------------------------------
// Engine errno → static string.  `int` parameter to fit the `n00b_result_t`
// errno idiom.
// ---------------------------------------------------------------------------

// Translate an algebra-side err code (`n00b_regex_algebra_err_t`, often
// surfaced via `n00b_result_get_err` on results whose payload comes from
// algebra / engine kernels) into the engine-facing enum.  Same mapping
// as `prefix.c::algebra_err_to_engine` / `stream.c`.  Without this, the
// raw cast in find_all_* paths drops STATE_SPACE_EXPLOSION (algebra=2)
// onto ALGEBRA (engine=2) instead of CAPACITY_EXCEEDED (engine=3).
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

const char *n00b_regex_engine_err_str(int kind)
{
    switch ((n00b_regex_engine_err_t)kind) {
    case N00B_REGEX_ENGINE_ERR_NONE:                return "ok";
    case N00B_REGEX_ENGINE_ERR_PARSE:               return "parse error";
    case N00B_REGEX_ENGINE_ERR_ALGEBRA:             return "algebra error";
    case N00B_REGEX_ENGINE_ERR_CAPACITY_EXCEEDED:   return "DFA state capacity exceeded";
    case N00B_REGEX_ENGINE_ERR_PATTERN_TOO_LARGE:   return "pattern too large";
    case N00B_REGEX_ENGINE_ERR_UNSUPPORTED_PATTERN: return "unsupported pattern";
    }
    return "unknown error";
}

// ---------------------------------------------------------------------------
// stream_cache_drop — defined here because StreamCache is owned by Regex.
// The forward-prefix accelerator is owned by `stream_cache.fwd_prefix`
// when populated; release through `fwd_prefix_search_free`.  The lazy-rev
// LDFA, when populated, lives on `RegexInner.rev` (released by
// `regex_inner_free`); the stream cache only owns the "inited" flag.
// ---------------------------------------------------------------------------

void stream_cache_drop(StreamCache *cache)
{
    if (!cache) return;
    if (n00b_atomic_load(&cache->fwd_prefix_inited) && cache->fwd_prefix) {
        fwd_prefix_search_free(cache->fwd_prefix);
        cache->fwd_prefix = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Edge / Graph (auto_harden support)
//
// File-local growable arrays — single-owner, single-thread under the
// builder.  Per § 7.5 mapping (b): use `n00b_list_new_private(T)`.  No
// rwlock overhead; same push/pop/get/set/len API.
// ---------------------------------------------------------------------------

typedef struct Edge {
    size_t dst;
    TSetId set;
} Edge;

// One `n00b_list_t(Edge) *` per node — ragged-by-row analog of resharp-c's
// `EdgeVec[]`.  Single-owner / single-thread under the builder, so each
// row uses `n00b_list_new_private` (no rwlock).
typedef struct GraphRows {
    n00b_list_t(Edge) **rows; /**< rows[i] is the per-node growable Edge list. */
    NodeId             *nodes;
    size_t              n;
    size_t              cap;
    n00b_allocator_t   *allocator;
} GraphRows;

static void graph_rows_init(GraphRows *g, n00b_allocator_t *allocator)
{
    *g = (GraphRows){.allocator = allocator};
}

static void graph_rows_free(GraphRows *g)
{
    if (g->rows) {
        for (size_t i = 0; i < g->n; ++i) {
            if (g->rows[i]) {
                n00b_list_free(*g->rows[i]);
                n00b_free(g->rows[i]);
            }
        }
        n00b_free(g->rows);
    }
    if (g->nodes) n00b_free(g->nodes);
    *g = (GraphRows){};
}

static size_t graph_rows_push_node(GraphRows *g, NodeId n)
{
    if (g->n == g->cap) {
        size_t nc = g->cap ? ckd_mul_sz_or_panic(g->cap, 2, "graph_rows.cap") : 8;

        n00b_list_t(Edge) **new_rows = n00b_alloc_array_with_opts(
            n00b_list_t(Edge) *, nc,
            &(n00b_alloc_opts_t){.allocator = g->allocator});
        NodeId             *new_nodes = n00b_alloc_array_with_opts(
            NodeId, nc,
            &(n00b_alloc_opts_t){.allocator = g->allocator,
                                 .scan_kind = N00B_GC_SCAN_KIND_NONE});
        if (g->n > 0) {
            memcpy(new_rows,  g->rows,  g->n * sizeof(*new_rows));
            memcpy(new_nodes, g->nodes, g->n * sizeof(*new_nodes));
        }
        if (g->rows)  n00b_free(g->rows);
        if (g->nodes) n00b_free(g->nodes);
        g->rows  = new_rows;
        g->nodes = new_nodes;
        g->cap   = nc;
    }
    g->rows[g->n]  = n00b_alloc_with_opts(
        n00b_list_t(Edge),
        &(n00b_alloc_opts_t){.allocator = g->allocator});
    *g->rows[g->n] = n00b_list_new_private(Edge, .allocator = g->allocator);
    g->nodes[g->n] = n;
    return g->n++;
}

// ---------------------------------------------------------------------------
// build_partial_graph
//
// Translation of resharp-c's NodeUSizeMap (HashMap<NodeId, size_t>) →
// `n00b_dict_t(NodeId, size_t)`.  NodeId is a 4-byte struct with no
// padding, so `skip_obj_hash = true` hashes the raw bytes.
// ---------------------------------------------------------------------------

typedef struct QueueEntry { size_t u; NodeId node; } QueueEntry;

typedef struct GraphBuildCtx {
    GraphRows               *g;
    n00b_dict_t(NodeId, size_t) *idx;
    n00b_list_t(QueueEntry) queue; /**< by-value; private list. */
    size_t                  budget;
    bool                    overflow;
    size_t                  cur_u;
} GraphBuildCtx;

static void iter_sat_collect_cb(void *user, RegexBuilder *b, NodeId next, TSetId set)
{
    (void)b;
    GraphBuildCtx *ctx = (GraphBuildCtx *)user;
    bool found;
    size_t dst = n00b_dict_get(ctx->idx, next, &found);
    if (!found) {
        if (ctx->g->n >= ctx->budget) {
            ctx->overflow = true;
            dst = SIZE_MAX;
            n00b_dict_put(ctx->idx, next, dst);
        } else {
            dst = graph_rows_push_node(ctx->g, next);
            n00b_dict_put(ctx->idx, next, dst);
            n00b_list_push(ctx->queue, ((QueueEntry){dst, next}));
        }
    }
    if (dst != SIZE_MAX) {
        n00b_list_push(*ctx->g->rows[ctx->cur_u], ((Edge){dst, set}));
    }
}

// returns true on success (graph populated), false on overflow / error.
static bool build_partial_graph(RegexBuilder *b, NodeId start, size_t budget,
                                GraphRows *out)
{
    n00b_allocator_t *alloc = regex_builder_allocator(b);
    graph_rows_init(out, alloc);

    n00b_dict_t(NodeId, size_t) *idx = n00b_alloc_with_opts(
        n00b_dict_t(NodeId, size_t),
        &(n00b_alloc_opts_t){.allocator = alloc});
    n00b_dict_init(idx, .skip_obj_hash = true, .allocator = alloc,
                   .scan_kind = N00B_GC_SCAN_KIND_NONE);

    GraphBuildCtx ctx = {
        .g        = out,
        .idx      = idx,
        .queue    = n00b_list_new_private(QueueEntry, .allocator = alloc),
        .budget   = budget,
        .overflow = false,
        .cur_u    = 0,
    };

    size_t start_idx = graph_rows_push_node(out, start);
    n00b_dict_put(idx, start, start_idx);
    n00b_list_push(ctx.queue, ((QueueEntry){start_idx, start}));

    bool ok = true;
    while (n00b_list_len(ctx.queue) > 0) {
        n00b_option_t(QueueEntry) popped = n00b_list_pop(QueueEntry, ctx.queue);
        if (!n00b_option_is_set(popped)) break;
        QueueEntry e = n00b_option_get(popped);

        auto sder_r = regex_builder_der(b, e.node, NULLABILITY_CENTER);
        if (!n00b_result_is_ok(sder_r)) { ok = false; break; }
        TRegexId sder = sder_r.ok;

        IterSatStack stack;
        iter_sat_stack_init(&stack);
        iter_sat_stack_push(&stack, (IterSatFrame){ sder, TSET_ID_FULL }, regex_builder_allocator(b));
        ctx.cur_u = e.u;
        regex_builder_iter_sat(b, &stack, &ctx, iter_sat_collect_cb);
        iter_sat_stack_free(&stack);
        if (ctx.overflow) { ok = false; break; }
    }

    n00b_list_free(ctx.queue);
    if (!ok) { graph_rows_free(out); return false; }
    return true;
}

// ---------------------------------------------------------------------------
// transitive_closure — row-major bool matrix.  Caller frees with n00b_free.
// ---------------------------------------------------------------------------

static bool *transitive_closure(const GraphRows *g)
{
    size_t n   = g->n;
    size_t nn  = ckd_mul_sz_or_panic(n, n, "transitive_closure: n*n");
    bool  *r   = n00b_alloc_array_with_opts(bool, nn,
                    &(n00b_alloc_opts_t){.allocator = g->allocator,
                                         .scan_kind = N00B_GC_SCAN_KIND_NONE});

    for (size_t i = 0; i < n; ++i) {
        n00b_list_t(Edge) *row = g->rows[i];
        size_t row_len = n00b_list_len(*row);
        for (size_t k = 0; k < row_len; ++k) {
            Edge ek = n00b_list_get(*row, k);
            r[i * n + ek.dst] = true;
        }
    }
    for (size_t k = 0; k < n; ++k) {
        for (size_t i = 0; i < n; ++i) {
            if (!r[i * n + k]) continue;
            for (size_t j = 0; j < n; ++j) {
                if (r[k * n + j]) r[i * n + j] = true;
            }
        }
    }
    return r;
}

// ---------------------------------------------------------------------------
// sccs_from_reach — list of `n00b_list_t(size_t) *` per SCC.
// ---------------------------------------------------------------------------

static n00b_list_t(n00b_list_t(size_t) *) sccs_from_reach(const bool *reach, size_t n,
                                                           n00b_allocator_t *allocator)
{
    n00b_list_t(n00b_list_t(size_t) *) sccs = n00b_list_new_private(
        n00b_list_t(size_t) *, .allocator = allocator);
    bool *visited = n00b_alloc_array_with_opts(bool, n,
                       &(n00b_alloc_opts_t){.allocator = allocator,
                                            .scan_kind = N00B_GC_SCAN_KIND_NONE});

    for (size_t i = 0; i < n; ++i) {
        if (visited[i]) continue;
        visited[i] = true;
        n00b_list_t(size_t) *scc = n00b_alloc_with_opts(
            n00b_list_t(size_t),
            &(n00b_alloc_opts_t){.allocator = allocator});
        *scc = n00b_list_new_private(size_t,
                   .allocator = allocator,
                   .scan_kind = N00B_GC_SCAN_KIND_NONE);
        n00b_list_push(*scc, i);
        for (size_t j = i + 1; j < n; ++j) {
            if (!visited[j] && reach[i * n + j] && reach[j * n + i]) {
                visited[j] = true;
                n00b_list_push(*scc, j);
            }
        }
        n00b_list_push(sccs, scc);
    }
    n00b_free(visited);
    return sccs;
}

static void sccs_free(n00b_list_t(n00b_list_t(size_t) *) *sccs)
{
    size_t n = n00b_list_len(*sccs);
    for (size_t i = 0; i < n; ++i) {
        n00b_list_t(size_t) *scc = n00b_list_get(*sccs, i);
        if (scc) {
            n00b_list_free(*scc);
            n00b_free(scc);
        }
    }
    n00b_list_free(*sccs);
}

// ---------------------------------------------------------------------------
// opener_class
// ---------------------------------------------------------------------------

typedef struct OpenerCtx { TSetId acc; } OpenerCtx;

static void opener_iter_cb(void *user, RegexBuilder *b, NodeId next, TSetId set)
{
    OpenerCtx *ctx = (OpenerCtx *)user;
    if (next.v > NODE_ID_BOT.v) {
        ctx->acc = solver_or_id(regex_builder_solver(b), ctx->acc, set);
    }
}

static TSetId opener_class(RegexBuilder *b, NodeId start)
{
    auto sder_r = regex_builder_der(b, start, NULLABILITY_CENTER);
    if (!n00b_result_is_ok(sder_r)) return TSET_ID_EMPTY;
    TRegexId sder = sder_r.ok;

    IterSatStack stack;
    iter_sat_stack_init(&stack);
    iter_sat_stack_push(&stack, (IterSatFrame){ sder, TSET_ID_FULL }, regex_builder_allocator(b));
    OpenerCtx ctx = { .acc = TSET_ID_EMPTY };
    regex_builder_iter_sat(b, &stack, &ctx, opener_iter_cb);
    iter_sat_stack_free(&stack);
    return ctx.acc;
}

// ---------------------------------------------------------------------------
// auto_harden
//
// Not a security measure: only flags obvious cases where hardening helps.
// ---------------------------------------------------------------------------

typedef struct Hardening {
    bool full;
    bool no_fwd_prefix;
} Hardening;

static Hardening auto_harden(RegexBuilder *b, NodeId start, bool has_anchors)
{
    constexpr size_t   NODE_BUDGET  = 128;
    constexpr uint32_t LARGE_COVER  = 128;
    constexpr uint32_t SHORT_PREFIX = 3;
    constexpr uint32_t ENTRY_BYTES  = 2;
    constexpr uint64_t SPIN_FREQ_THRESHOLD = TOTAL_BYTE_FREQ / 2;

    Hardening empty = (Hardening){false, false};

    TSetId opener = opener_class(b, start);
    if (opener.v == TSET_ID_EMPTY.v) return empty;

    Solver *sv = regex_builder_solver(b);
    bool opener_full = solver_is_full_id(sv, opener);

    GraphRows graph;
    if (!build_partial_graph(b, start, NODE_BUDGET, &graph)) return empty;

    Hardening result        = empty;
    bool      no_fwd_prefix = false;

    n00b_allocator_t *alloc = regex_builder_allocator(b);
    bool   *reach     = nullptr;
    n00b_list_t(n00b_list_t(size_t) *) sccs = n00b_list_new_private(
        n00b_list_t(size_t) *, .allocator = alloc);
    size_t *node_scc  = nullptr;
    bool   *pure_star = nullptr;
    bool   *scc_set   = nullptr;
    bool    have_sccs = false;

    // fail-fast: any Compl?
    for (size_t i = 0; i < graph.n; ++i) {
        if (regex_builder_get_kind(b, graph.nodes[i]) == KIND_COMPL) {
            goto cleanup;
        }
    }

    pure_star = n00b_alloc_array_with_opts(bool, graph.n,
        &(n00b_alloc_opts_t){.allocator = alloc,
                             .scan_kind = N00B_GC_SCAN_KIND_NONE});
    for (size_t i = 0; i < graph.n; ++i) {
        if (i == 0) continue;
        Nullability nu = nodeid_nullability(graph.nodes[i], b);
        if (!nullability_eq(nu, NULLABILITY_ALWAYS)) continue;

        n00b_list_t(Edge) *row = graph.rows[i];
        if (n00b_list_len(*row) == 1) {
            Edge e = n00b_list_get(*row, 0);
            if (e.dst == i && solver_is_full_id(sv, e.set)) {
                pure_star[i] = true;
            }
        }
    }

    {
        n00b_list_t(Edge) *row0 = graph.rows[0];
        if (!has_anchors
            && n00b_list_len(*row0) == 1) {
            Edge e0 = n00b_list_get(*row0, 0);
            if (e0.dst == 0 && solver_is_full_id(sv, e0.set)) {
                goto cleanup;
            }
        }
    }

    reach     = transitive_closure(&graph);
    sccs      = sccs_from_reach(reach, graph.n, alloc);
    have_sccs = true;

    node_scc = n00b_alloc_array_with_opts(size_t, graph.n,
        &(n00b_alloc_opts_t){.allocator = alloc,
                             .scan_kind = N00B_GC_SCAN_KIND_NONE});
    // Hoisted SCC-membership scratch buffer: reused across both per-SCC loops
    // below via memset rather than per-iteration alloc/free.
    scc_set  = n00b_alloc_array_with_opts(bool, graph.n,
        &(n00b_alloc_opts_t){.allocator = alloc,
                             .scan_kind = N00B_GC_SCAN_KIND_NONE});
    {
        size_t scc_count = n00b_list_len(sccs);
        for (size_t sid = 0; sid < scc_count; ++sid) {
            n00b_list_t(size_t) *scc = n00b_list_get(sccs, sid);
            size_t scc_len = n00b_list_len(*scc);
            for (size_t k = 0; k < scc_len; ++k) {
                node_scc[n00b_list_get(*scc, k)] = sid;
            }
        }
    }

    bool start_in_cycle;
    {
        n00b_list_t(size_t) *scc0 = n00b_list_get(sccs, node_scc[0]);
        start_in_cycle = n00b_list_len(*scc0) > 1;
        if (!start_in_cycle) {
            n00b_list_t(Edge) *row0 = graph.rows[0];
            size_t row0_len = n00b_list_len(*row0);
            for (size_t k = 0; k < row0_len; ++k) {
                Edge ek = n00b_list_get(*row0, k);
                if (ek.dst == 0) { start_in_cycle = true; break; }
            }
        }
    }

    size_t total_wide_self_loops = 0;
    for (size_t i = 0; i < graph.n; ++i) {
        if (pure_star[i]) continue;
        TSetId self_cov = TSET_ID_EMPTY;
        n00b_list_t(Edge) *row = graph.rows[i];
        size_t row_len = n00b_list_len(*row);
        for (size_t k = 0; k < row_len; ++k) {
            Edge ek = n00b_list_get(*row, k);
            if (ek.dst == i) self_cov = solver_or_id(sv, self_cov, ek.set);
        }
        if (solver_byte_count(sv, self_cov) >= 2) total_wide_self_loops += 1;
    }

    MinMax   mm_start = regex_builder_get_min_max_length(b, start);
    uint32_t min_len  = mm_start.min;

    for (size_t i = 0; i < graph.n; ++i) {
        Nullability nu = nodeid_nullability(graph.nodes[i], b);
        if (nullability_eq(nu, NULLABILITY_NEVER)) continue;
        n00b_list_t(size_t) *scc = n00b_list_get(sccs, node_scc[i]);
        size_t scc_len = n00b_list_len(*scc);
        bool scc_non_trivial = scc_len > 1;
        if (!scc_non_trivial) {
            n00b_list_t(Edge) *row = graph.rows[i];
            size_t row_len = n00b_list_len(*row);
            for (size_t k = 0; k < row_len; ++k) {
                Edge ek = n00b_list_get(*row, k);
                if (ek.dst == i) { scc_non_trivial = true; break; }
            }
        }
        if (!scc_non_trivial) continue;

        // scc_set membership as bool array indexed by node — scratch buffer
        // hoisted; reset between iterations.
        memset(scc_set, 0, graph.n * sizeof(bool));
        for (size_t k = 0; k < scc_len; ++k) scc_set[n00b_list_get(*scc, k)] = true;

        TSetId in_scc_cov = TSET_ID_EMPTY;
        n00b_list_t(Edge) *row = graph.rows[i];
        size_t row_len = n00b_list_len(*row);
        for (size_t k = 0; k < row_len; ++k) {
            Edge ek = n00b_list_get(*row, k);
            if (scc_set[ek.dst]) in_scc_cov = solver_or_id(sv, in_scc_cov, ek.set);
        }
        if (solver_byte_count(sv, in_scc_cov) < LARGE_COVER) {
            continue;
        }
        if (i == 0) {
            result = (Hardening){true, true};
            goto cleanup;
        }

        TSetId start_to_i = TSET_ID_EMPTY;
        n00b_list_t(Edge) *row0 = graph.rows[0];
        size_t row0_len = n00b_list_len(*row0);
        for (size_t k = 0; k < row0_len; ++k) {
            Edge ek = n00b_list_get(*row0, k);
            if (ek.dst == i) start_to_i = solver_or_id(sv, start_to_i, ek.set);
        }
        bool entry_wide = solver_byte_count(sv, start_to_i) >= ENTRY_BYTES;
        if (!has_anchors && min_len <= SHORT_PREFIX && entry_wide) {
            result = (Hardening){true, true};
            goto cleanup;
        }
    }

    bool opener_wide = opener_full || solver_byte_count(sv, opener) >= LARGE_COVER;
    {
        size_t scc_count = n00b_list_len(sccs);
        for (size_t s = 0; s < scc_count; ++s) {
            n00b_list_t(size_t) *scc = n00b_list_get(sccs, s);
            size_t scc_len = n00b_list_len(*scc);

            bool non_trivial = scc_len > 1;
            if (!non_trivial) {
                size_t only = n00b_list_get(*scc, 0);
                n00b_list_t(Edge) *row = graph.rows[only];
                size_t row_len = n00b_list_len(*row);
                for (size_t k = 0; k < row_len; ++k) {
                    Edge ek = n00b_list_get(*row, k);
                    if (ek.dst == only) { non_trivial = true; break; }
                }
            }
            if (!non_trivial) continue;

            bool all_pure_star = true;
            for (size_t k = 0; k < scc_len; ++k) {
                if (!pure_star[n00b_list_get(*scc, k)]) { all_pure_star = false; break; }
            }
            if (all_pure_star) continue;

            memset(scc_set, 0, graph.n * sizeof(bool));
            for (size_t k = 0; k < scc_len; ++k) scc_set[n00b_list_get(*scc, k)] = true;
            if (scc_set[0]) { continue; } // (3b) start in SCC

            bool sticky = true;
            for (size_t k = 0; k < scc_len; ++k) {
                size_t nidx = n00b_list_get(*scc, k);
                TSetId cover = TSET_ID_EMPTY;
                n00b_list_t(Edge) *row = graph.rows[nidx];
                size_t row_len = n00b_list_len(*row);
                for (size_t e = 0; e < row_len; ++e) {
                    Edge ek = n00b_list_get(*row, e);
                    cover = solver_or_id(sv, cover, ek.set);
                }
                if (!solver_is_full_id(sv, cover)) { sticky = false; break; }
            }

            bool has_wide_spin = false;
            for (size_t k = 0; k < scc_len && !has_wide_spin; ++k) {
                size_t nidx = n00b_list_get(*scc, k);
                TSetId in_scc_cover = TSET_ID_EMPTY;
                n00b_list_t(Edge) *row = graph.rows[nidx];
                size_t row_len = n00b_list_len(*row);
                for (size_t e = 0; e < row_len; ++e) {
                    Edge ek = n00b_list_get(*row, e);
                    if (scc_set[ek.dst]) {
                        in_scc_cover = solver_or_id(sv, in_scc_cover, ek.set);
                    }
                }
                uint8_t *bytes = nullptr; size_t bytes_len = 0;
                solver_collect_bytes(sv, in_scc_cover, &bytes, &bytes_len);
                uint64_t freq = 0;
                for (size_t bi = 0; bi < bytes_len; ++bi) {
                    freq += (uint64_t)n00b_simd_BYTE_FREQ[bytes[bi]];
                }
                // n00b's solver_collect_bytes returns GC-managed bytes — no free.
                if (freq >= SPIN_FREQ_THRESHOLD) has_wide_spin = true;
            }
            if (!has_wide_spin) { continue; }

            bool restartable = false;
            for (size_t k = 0; k < scc_len && !restartable; ++k) {
                size_t nidx = n00b_list_get(*scc, k);
                n00b_list_t(Edge) *row = graph.rows[nidx];
                size_t row_len = n00b_list_len(*row);
                for (size_t e = 0; e < row_len; ++e) {
                    Edge ek = n00b_list_get(*row, e);
                    if (scc_set[ek.dst] && solver_is_sat_id(sv, ek.set, opener)) {
                        restartable = true;
                        break;
                    }
                }
            }
            if (!restartable) { continue; }

            if (!has_anchors) {
                no_fwd_prefix = true;
            }

            n00b_list_t(Edge) *row0_local = graph.rows[0];
            bool start_branches = n00b_list_len(*row0_local) >= 2;
            bool scc_branches = false;
            for (size_t k = 0; k < scc_len; ++k) {
                size_t nidx = n00b_list_get(*scc, k);
                if (n00b_list_len(*graph.rows[nidx]) >= 3) { scc_branches = true; break; }
            }
            if (!start_branches && total_wide_self_loops <= 1) {
                continue;
            }

            bool start_escapes_scc;
            if (has_anchors) {
                size_t into = 0;
                size_t row0_len = n00b_list_len(*row0_local);
                for (size_t k = 0; k < row0_len; ++k) {
                    Edge ek = n00b_list_get(*row0_local, k);
                    if (scc_set[ek.dst]) into += 1;
                }
                start_escapes_scc = row0_len > into;
            } else {
                TSetId cover = TSET_ID_EMPTY;
                size_t row0_len = n00b_list_len(*row0_local);
                for (size_t k = 0; k < row0_len; ++k) {
                    Edge ek = n00b_list_get(*row0_local, k);
                    bool in_or_reaches = scc_set[ek.dst];
                    if (!in_or_reaches) {
                        for (size_t kk = 0; kk < scc_len; ++kk) {
                            size_t scc_n = n00b_list_get(*scc, kk);
                            if (reach[ek.dst * graph.n + scc_n]) {
                                in_or_reaches = true; break;
                            }
                        }
                    }
                    if (in_or_reaches) cover = solver_or_id(sv, cover, ek.set);
                }
                start_escapes_scc = !solver_is_full_id(sv, cover);
            }

            if (start_escapes_scc && !start_in_cycle) { continue; }
            if (sticky && opener_wide && (start_branches || scc_branches)) {
                result = (Hardening){true, true};
                goto cleanup;
            }
        }
    }

    if (no_fwd_prefix) {
        result = (Hardening){false, true};
    }

cleanup:
    if (pure_star) n00b_free(pure_star);
    if (node_scc)  n00b_free(node_scc);
    if (scc_set)   n00b_free(scc_set);
    if (reach)     n00b_free(reach);
    if (have_sccs) sccs_free(&sccs);
    else           n00b_list_free(sccs);
    graph_rows_free(&graph);
    return result;
}

// ---------------------------------------------------------------------------
// ensure_supported
// ---------------------------------------------------------------------------

static n00b_regex_engine_err_t ensure_supported(RegexBuilder *b, NodeId node)
{
    if (!nodeid_contains_lookaround(node, b)) return N00B_REGEX_ENGINE_ERR_NONE;
    Kind k = regex_builder_get_kind(b, node);
    switch (k) {
    case KIND_UNION: {
        NodeId l = nodeid_left(node, b);
        NodeId r = nodeid_right(node, b);
        if (nodeid_contains_lookbehind(l, b) || nodeid_contains_lookbehind(r, b)) {
            return N00B_REGEX_ENGINE_ERR_UNSUPPORTED_PATTERN;
        }
        return N00B_REGEX_ENGINE_ERR_NONE;
    }
    case KIND_CONCAT:
    case KIND_INTER: {
        n00b_regex_engine_err_t e = ensure_supported(b, nodeid_left(node, b));
        if (e != N00B_REGEX_ENGINE_ERR_NONE) return e;
        return ensure_supported(b, nodeid_right(node, b));
    }
    case KIND_STAR: {
        NodeId inner = nodeid_left(node, b);
        if (nodeid_contains_lookaround(inner, b)) {
            return N00B_REGEX_ENGINE_ERR_UNSUPPORTED_PATTERN;
        }
        return ensure_supported(b, inner);
    }
    case KIND_COUNTED:
    case KIND_COMPL:
        return ensure_supported(b, nodeid_left(node, b));
    case KIND_LOOKBEHIND:
    case KIND_LOOKAHEAD: {
        n00b_regex_engine_err_t e = ensure_supported(b, nodeid_left(node, b));
        if (e != N00B_REGEX_ENGINE_ERR_NONE) return e;
        return ensure_supported(b, nodeid_right(node, b));
    }
    case KIND_PRED:
    case KIND_BEGIN:
    case KIND_END:
        return N00B_REGEX_ENGINE_ERR_NONE;
    }
    return N00B_REGEX_ENGINE_ERR_NONE;
}

// ---------------------------------------------------------------------------
// matches!() helpers — local PrefixKind probes.
// ---------------------------------------------------------------------------

static bool prefix_is_some_fwd(const PrefixKind *p)
{
    if (!p) return false;
    PrefixKindTag t = prefix_kind_tag(p);
    return t == PREFIX_KIND_ANCHORED_FWD
        || t == PREFIX_KIND_ANCHORED_FWD_LB;
}

static bool prefix_is_anchored_fwd_lb(const PrefixKind *p)
{
    return p && prefix_kind_tag(p) == PREFIX_KIND_ANCHORED_FWD_LB;
}

static bool prefix_is_anchored_fwd_either(const PrefixKind *p)
{
    if (!p) return false;
    PrefixKindTag t = prefix_kind_tag(p);
    return t == PREFIX_KIND_ANCHORED_FWD || t == PREFIX_KIND_ANCHORED_FWD_LB;
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

static n00b_regex_engine_err_t from_node_inner(RegexBuilder *b, NodeId node,
                                                RegexOptions opts,
                                                size_t pattern_len, Regex *out,
                                                n00b_allocator_t *allocator);

Regex *regex_new(const char *pattern)
{
    if (pattern == nullptr) return nullptr;
    return regex_with_options(pattern, regex_options_default());
}

static n00b_regex_engine_err_t regex_with_options_into(const char *pattern,
                                                        RegexOptions opts,
                                                        Regex *out,
                                                        n00b_allocator_t *allocator);

Regex *regex_with_options(const char *pattern, RegexOptions opts)
{
    if (pattern == nullptr) return nullptr;
    Regex *r = n00b_alloc(Regex);
    /* Allocate the pool *struct* in the pinned system_pool (NOT in r
     * itself).  The Regex lives in the movable GC arena; every
     * regex-internal site caches the resulting n00b_allocator_t *,
     * which must remain valid across any GC compaction that moves r.
     * The system_pool is pinned, so addresses we hand out from here
     * never move. */
    n00b_runtime_t *rt = n00b_get_runtime();
    r->pool = n00b_alloc_with_opts(
        n00b_pool_t, &(n00b_alloc_opts_t){
            .allocator = (n00b_allocator_t *)&rt->system_pool,
        });
    /* The GC does NOT scan pool memory for pool→default-heap pointers, so
     * anything the regex references must live in THIS pool (not the movable
     * default heap) to survive a collection.  In particular the SIMD search
     * accelerators are allocated into this pool at their construction sites
     * via n00b_set_current_allocator (see prefix.c / bdfa.c / engine.c);
     * otherwise the default-heap payload is reclaimed and the pool's pointer
     * to it dangles. */
    n00b_allocator_t *alloc = n00b_pool_init(r->pool,
                                              .__system = true,
                                              .name     = "regex_compile");
    r->pool_owned = true;
    n00b_regex_engine_err_t err = regex_with_options_into(pattern, opts, r, alloc);
    if (err != N00B_REGEX_ENGINE_ERR_NONE) {
        n00b_allocator_destroy((n00b_allocator_t *)r->pool);
        r->pool_owned = false;
        n00b_free(r);
        return nullptr;
    }
    return r;
}

static n00b_regex_engine_err_t regex_with_options_into(const char *pattern,
                                                        RegexOptions opts,
                                                        Regex *out,
                                                        n00b_allocator_t *allocator)
{
    n00b_require(pattern != nullptr, "regex_with_options_into: pattern must not be NULL");
    n00b_require(out     != nullptr, "regex_with_options_into: out must not be NULL");

    RegexBuilder *b = regex_builder_new(allocator);
    regex_builder_set_lookahead_context_max(b, opts.lookahead_context_max);

    PatternFlagsLayout pflags = {
        .unicode             = opts.unicode != UNICODE_MODE_ASCII,
        .full_unicode        = opts.unicode == UNICODE_MODE_FULL,
        .ascii_perl_classes  = opts.unicode == UNICODE_MODE_JAVASCRIPT,
        .case_insensitive    = opts.case_insensitive,
        .dot_matches_new_line = opts.dot_matches_new_line,
        .multiline           = opts.multiline,
        .ignore_whitespace   = opts.ignore_whitespace,
        .expanded_ast_limit  = opts.unbounded_size ? UINT64_MAX
                                                   : DEFAULT_EXPANDED_AST_LIMIT,
        .max_list_len        = opts.unbounded_size ? SIZE_MAX
                                                   : DEFAULT_MAX_LIST_LEN,
    };

    struct ParseError *parse_err = nullptr;
    NodeId node = parser_parse_ast_with(b, pattern,
                                        (const struct PatternFlags *)&pflags,
                                        &parse_err);
    if (parse_err) {
        regex_builder_free(b);
        ParseError_free(parse_err);
        return N00B_REGEX_ENGINE_ERR_PARSE;
    }

    // strlen — internal char* per user note 17 narrow license; libc-free
    // alternative is unnecessary for a single null-terminated pattern.
    size_t pattern_len = 0;
    while (pattern[pattern_len] != '\0') pattern_len++;
    return from_node_inner(b, node, opts, pattern_len, out, allocator);
}

n00b_regex_engine_err_t regex_from_node(RegexBuilder *b, NodeId node,
                                         RegexOptions opts, Regex *out)
{
    /* regex_from_node is the caller-already-has-a-builder entrypoint
     * (used by precompile/serialize paths).  It does NOT own a pool —
     * the caller's builder lives wherever it was created.  Internal
     * compile-time allocations fall back to runtime default. */
    return from_node_inner(b, node, opts, 0, out, nullptr);
}

static n00b_regex_engine_err_t from_node_inner(RegexBuilder *b, NodeId node,
                                                RegexOptions opts,
                                                size_t pattern_len, Regex *out,
                                                n00b_allocator_t *allocator)
{
    (void)allocator; /* threaded into callees by Step 5 internals adoption. */
    size_t node_limit = opts.unbounded_size ? SIZE_MAX : (size_t)200000;
    if (regex_builder_tree_size(b, node, node_limit) >= node_limit) {
        regex_builder_free(b);
        return N00B_REGEX_ENGINE_ERR_PATTERN_TOO_LARGE;
    }
    n00b_regex_engine_err_t err = ensure_supported(b, node);
    if (err != N00B_REGEX_ENGINE_ERR_NONE) {
        regex_builder_free(b);
        return err;
    }

    bool empty_nullable = nullability_has(
        regex_builder_nullability_emptystring(b, node), NULLABILITY_EMPTYSTRING);
    Nullability initial_nullability = regex_builder_nullability(b, node);

    node = regex_builder_simplify_fwd_initial(b, node);
    NodeId fwd_start;
    {
        auto strip_r = regex_builder_strip_lb(b, node);
        if (!n00b_result_is_ok(strip_r)) {
            n00b_regex_engine_err_t e
                = algebra_err_to_engine(n00b_result_get_err(strip_r));
            regex_builder_free(b);
            return e;
        }
        fwd_start = strip_r.ok;
    }
    bool fwd_end_nullable = nullability_has(
        regex_builder_nullability(b, fwd_start), NULLABILITY_END);

    NodeId ts_rev_start;
    {
        auto trs_r = regex_builder_ts_rev_start(b, node);
        if (!n00b_result_is_ok(trs_r)) {
            n00b_regex_engine_err_t e
                = algebra_err_to_engine(n00b_result_get_err(trs_r));
            regex_builder_free(b);
            return e;
        }
        ts_rev_start = trs_r.ok;
    }

    bool is_empty_lang = (node.v == NODE_ID_BOT.v);
    bool fwd_begin_anchored =
        (node.v == NODE_ID_BEGIN.v)
        || (regex_builder_get_kind(b, node) == KIND_CONCAT
            && nodeid_left(node, b).v == NODE_ID_BEGIN.v);

    bool rev_trivial = nullability_eq(regex_builder_nullability(b, ts_rev_start),
                                      NULLABILITY_ALWAYS);

    uint32_t fixed_length_v;
    bool has_fixed_length = regex_builder_get_fixed_length(b, node, &fixed_length_v);

    MinMax mm_node = regex_builder_get_min_max_length(b, node);
    uint32_t min_len = mm_node.min;
    uint32_t max_len = mm_node.max;
    bool has_max_length = (max_len != UINT32_MAX);

    bool has_look = regex_builder_contains_look(b, node);

    size_t max_cap = opts.max_dfa_capacity;
    if (max_cap > (size_t)UINT16_MAX) max_cap = (size_t)UINT16_MAX;

    // Default to hardened when the default dispatch would be pathological.
    bool has_anchors_pre = regex_builder_contains_anchors(b, node);
    Hardening ah = auto_harden(b, fwd_start, has_anchors_pre);
    if (!opts.hardened && ah.full) {
        opts.hardened = true;
    }

    PrefixSelect sel = (PrefixSelect){};
    void *psp_err = prefix_select_prefix(b, node, ts_rev_start, has_look,
                                          min_len, max_cap,
                                          ah.no_fwd_prefix, &sel);
    if (psp_err != nullptr) {
        err = (n00b_regex_engine_err_t)*(int *)psp_err;
        n00b_free(psp_err);
        regex_builder_free(b);
        return err;
    }

    // `sel.kind` is a value; copy onto the heap so `Regex.prefix` (a
    // `PrefixKind *` owned by Regex) follows existing ownership rules.
    PrefixKind *selected = nullptr;
    if (sel.has_kind) {
        selected  = n00b_alloc_with_opts(
            PrefixKind, &(n00b_alloc_opts_t){.allocator = allocator});
        *selected = sel.kind;
    }
    RevTeddySearch *sel_rev_skip = sel.has_skip ? sel.skip : nullptr;

    bool        rev_skip_transferred = false;
    LDFA       *fwd                 = nullptr;
    LDFA       *fwd_ts              = nullptr;
    LDFA       *rev_ts              = nullptr;
    BDFA       *bounded             = nullptr;
    FwdDFA     *fas                 = nullptr;

    bool has_fwd_prefix = prefix_is_some_fwd(selected);

    bool anchored_fwd = prefix_is_anchored_fwd_either(selected);
    bool needs_full_fwd = opts.hardened || anchored_fwd;

    {
        n00b_result_t(LDFA *) r = needs_full_fwd
            ? engine_LDFA_new(b, fwd_start, max_cap)
            : engine_LDFA_new_fwd(b, fwd_start, max_cap);
        if (!n00b_result_is_ok(r)) {
            err = algebra_err_to_engine(n00b_result_get_err(r));
            goto fail;
        }
        fwd = n00b_result_get(r);
    }

    NodeId ts_fwd_start;
    {
        NodeId with_ts = regex_builder_mk_concat(b, NODE_ID_TS, node);
        ts_fwd_start = regex_builder_simplify_fwd_initial(b, with_ts);
    }
    {
        n00b_result_t(LDFA *) r = engine_LDFA_new_fwd(b, ts_fwd_start, max_cap);
        if (!n00b_result_is_ok(r)) {
            err = algebra_err_to_engine(n00b_result_get_err(r));
            goto fail;
        }
        fwd_ts = n00b_result_get(r);
    }

    {
        n00b_result_t(LDFA *) r = engine_LDFA_new(b, ts_rev_start, max_cap);
        if (!n00b_result_is_ok(r)) {
            err = algebra_err_to_engine(n00b_result_get_err(r));
            goto fail;
        }
        rev_ts = n00b_result_get(r);
    }
    engine_LDFA_set_prefix_skip(rev_ts, sel_rev_skip);
    rev_skip_transferred = true;
    engine_LDFA_ensure_pruned_skip(rev_ts);

    StreamInit stream_init;
    {
        NodeId fwd_pruned = regex_builder_prune_begin_eps(b, ts_fwd_start);
        NodeId rev_pruned = regex_builder_prune_begin_eps(b, ts_rev_start);
        stream_init.start_node = node;
        stream_init.seek_fwd = (uint32_t)engine_LDFA_get_or_register(fwd_ts, b, fwd_pruned);
        stream_init.seek_rev = (uint32_t)engine_LDFA_get_or_register(rev_ts, b, rev_pruned);
    }

    bool    fwd_lb_begin_nullable = false;
    uint8_t lb_check_bytes = 0;
    if (prefix_is_anchored_fwd_lb(selected)) {
        NodeId lb_inner   = regex_builder_get_lookbehind_inner(b, nodeid_left(node, b));
        NodeId lb_nonbegin = regex_builder_nonbegins(b, lb_inner);
        NodeId lb_strip   = lb_nonbegin;
        for (;;) {
            NodeId after_strip = regex_builder_strip_prefix_safe(b, lb_strip);
            NodeId after_nb    = regex_builder_nonbegins(b, after_strip);
            if (after_nb.v == lb_strip.v) break;
            lb_strip = after_nb;
        }
        uint32_t lb_fixed;
        bool has_lb_fixed = regex_builder_get_fixed_length(b, lb_strip, &lb_fixed);
        n00b_require(has_lb_fixed, "AnchoredFwdLb requires fixed-length lb");
        bool begin_nullable = nullability_has(
            regex_builder_nullability(b, lb_inner), NULLABILITY_BEGIN);
        fwd_lb_begin_nullable = begin_nullable;
        lb_check_bytes = (uint8_t)lb_fixed;
    }

    bool use_bounded =
        !has_fwd_prefix
        && has_max_length
        && max_len <= 100
        && !has_fixed_length
        && !has_look
        && !regex_builder_contains_anchors(b, node)
        && pattern_len <= 150
        && !empty_nullable;

    if (use_bounded) {
        n00b_result_t(BDFA *) br = bdfa_new(b, fwd_start);
        if (!n00b_result_is_ok(br)) {
            err = algebra_err_to_engine(n00b_result_get_err(br));
            goto fail;
        }
        bounded = n00b_result_get(br);
    }

    bool has_bounded_local        = (bounded != nullptr);
    bool has_bounded_prefix_local = bounded && bdfa_prefix_is_some(bounded);

    bool has_anchors = regex_builder_contains_anchors(b, node);

    bool hardened = false;
    if (opts.hardened && !has_bounded_local && !has_fixed_length && max_cap >= 64) {
        hardened = engine_LDFA_has_nonnullable_cycle(fwd, b, 256);
    }

    if (hardened) {
        fas = fas_FwdDFA_new(fwd, nodeid_contains_lookahead(fwd_start, b));
    }

    // Build RegexInner on heap.
    RegexInner *inner = n00b_alloc_with_opts(
        RegexInner, &(n00b_alloc_opts_t){.allocator = allocator});
    inner->b        = b;
    inner->fwd      = fwd;
    inner->fwd_ts   = fwd_ts;
    inner->rev      = nullptr; /* lazily inited via stream_cache.rev_inited. */
    inner->rev_ts   = rev_ts;
    inner->stream   = stream_init;

    inner->nulls    = n00b_alloc_with_opts(
        n00b_list_t(size_t), &(n00b_alloc_opts_t){.allocator = allocator});
    *inner->nulls   = n00b_list_new_private(size_t,
        .allocator = allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    inner->matches  = n00b_alloc_with_opts(
        n00b_list_t(Match), &(n00b_alloc_opts_t){.allocator = allocator});
    *inner->matches = n00b_list_new_private(Match,
        .allocator = allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE);

    inner->bounded  = bounded;
    inner->fas      = fas;

    n00b_mutex_init(&out->inner_lock);
    out->inner                       = inner;
    out->prefix                      = selected;
    out->has_fixed_length            = has_fixed_length;
    out->fixed_length                = fixed_length_v;
    out->empty_nullable              = empty_nullable;
    out->always_nullable             = nullability_eq(initial_nullability, NULLABILITY_ALWAYS);
    out->is_empty_lang               = is_empty_lang;
    out->fwd_begin_anchored          = fwd_begin_anchored;
    out->rev_trivial                 = rev_trivial;
    out->initial_nullability         = initial_nullability;
    out->fwd_end_nullable            = fwd_end_nullable;
    out->hardened                    = hardened;
    out->has_bounded_prefix          = has_bounded_prefix_local;
    out->has_bounded                 = has_bounded_local;
    out->lb_check_bytes              = lb_check_bytes;
    out->fwd_lb_begin_nullable       = fwd_lb_begin_nullable;
    out->has_anchors                 = has_anchors;
    out->stream_cache                = (StreamCache){};
    return N00B_REGEX_ENGINE_ERR_NONE;

fail:
    if (fas)      fas_FwdDFA_free(fas);
    if (bounded)  bdfa_free(bounded);
    if (rev_ts)   engine_LDFA_free(rev_ts);
    if (fwd_ts)   engine_LDFA_free(fwd_ts);
    if (fwd)      engine_LDFA_free(fwd);
    if (selected) prefix_kind_free(selected);
    if (!rev_skip_transferred && sel_rev_skip) prefix_rev_skip_free(sel_rev_skip);
    regex_builder_free(b);
    return err;
}

static void regex_inner_free(RegexInner *inner)
{
    if (!inner) return;
    if (inner->fas)     fas_FwdDFA_free(inner->fas);
    if (inner->bounded) bdfa_free(inner->bounded);
    if (inner->rev_ts)  engine_LDFA_free(inner->rev_ts);
    if (inner->rev)     engine_LDFA_free(inner->rev);
    if (inner->fwd_ts)  engine_LDFA_free(inner->fwd_ts);
    if (inner->fwd)     engine_LDFA_free(inner->fwd);
    if (inner->b)       regex_builder_free(inner->b);
    if (inner->matches) {
        n00b_list_free(*inner->matches);
        n00b_free(inner->matches);
    }
    if (inner->nulls) {
        n00b_list_free(*inner->nulls);
        n00b_free(inner->nulls);
    }
    n00b_free(inner);
}

void regex_free(Regex *r)
{
    if (!r) return;
    // stream_cache resources (FwdPrefixSearch on the heap) live on the
    // public Regex, not on RegexInner — release them before the inner
    // teardown.
    stream_cache_drop(&r->stream_cache);
    if (r->pool_owned) {
        /* Pool destroy reclaims every allocation made via r->pool
         * (RegexInner, builder, LDFAs, lists, dicts, BDFA, FAS, etc.)
         * in one shot, regardless of granular ownership.  The inner
         * field is still useful to null for assertion purposes. */
        r->inner = nullptr;
        r->prefix = nullptr;
        n00b_allocator_destroy((n00b_allocator_t *)r->pool);
        r->pool_owned = false;
    }
    else {
        regex_inner_free(r->inner);
        r->inner = nullptr;
        if (r->prefix) {
            prefix_kind_free(r->prefix);
            r->prefix = nullptr;
        }
    }
    n00b_free(r);
}

// ---------------------------------------------------------------------------
// Read-only accessors
// ---------------------------------------------------------------------------

void regex_has_accel(const Regex *r, bool *fwd_accel, bool *rev_accel)
{
    if (!r) {
        if (fwd_accel) *fwd_accel = false;
        if (rev_accel) *rev_accel = false;
        return;
    }
    bool fwd = (r->prefix != nullptr && prefix_kind_is_fwd(r->prefix));
    bool rev = (r->prefix != nullptr && prefix_kind_is_rev(r->prefix));
    if (!rev && r->inner != nullptr) {
        n00b_mutex_lock((n00b_mutex_t *)&r->inner_lock);
        if (r->inner->rev_ts != nullptr && engine_LDFA_can_skip(r->inner->rev_ts)) {
            rev = true;
        }
        n00b_mutex_unlock((n00b_mutex_t *)&r->inner_lock);
    }
    if (fwd_accel) *fwd_accel = fwd;
    if (rev_accel) *rev_accel = rev;
}

bool regex_bdfa_stats_is_some(const Regex *r)
{
    if (!r) return false;
    return r->has_bounded;
}

static bool rev_nulls_debug_has_terminal_center_run(
    const n00b_list_t(size_t) *nulls)
{
    // Debug parity: long reverse center-null runs that reach byte 0 expose
    // both the CENTER and END null at 0.  Public match collection keeps using
    // the raw scan vector; this only expands the diagnostic clone below.
    size_t n = n00b_list_len(*nulls);
    if (n < 4) return false;

    size_t expect = 0;
    size_t run    = 0;
    for (size_t i = n; i > 0; --i) {
        size_t v = n00b_list_get(*nulls, i - 1);
        if (v != expect) break;
        ++run;
        ++expect;
    }
    return run >= 4;
}

n00b_list_t(size_t) *regex_collect_rev_nulls_debug(const Regex *r,
                                                    const uint8_t *input,
                                                    size_t input_len)
{
    if (!r || input == nullptr || input_len == 0) return nullptr;
    n00b_mutex_lock((n00b_mutex_t *)&r->inner_lock);
    n00b_list_clear(*r->inner->nulls);
    n00b_result_t(int) cr_r = engine_LDFA_collect_rev(
        r->inner->rev_ts, r->inner->b,
        input_len - 1, input, input_len,
        r->inner->nulls);
    if (!n00b_result_is_ok(cr_r)) {
        n00b_list_clear(*r->inner->nulls);
        n00b_mutex_unlock((n00b_mutex_t *)&r->inner_lock);
        return nullptr;
    }
    if (rev_nulls_debug_has_terminal_center_run(r->inner->nulls)) {
        n00b_list_push(*r->inner->nulls, 0);
    }
    size_t n = n00b_list_len(*r->inner->nulls);

    // Canonical idiom: populate a fully scan-info-threaded lvalue
    // first, then struct-copy into the heap-allocated return shell.
    n00b_list_t(size_t) lst =
        n00b_list_new_private(size_t, .scan_kind = N00B_GC_SCAN_KIND_NONE);
    for (size_t i = 0; i < n; ++i) {
        n00b_list_push(lst, n00b_list_get(*r->inner->nulls, i));
    }

    n00b_list_t(size_t) *out = n00b_alloc(n00b_list_t(size_t));
    *out = lst;
    n00b_mutex_unlock((n00b_mutex_t *)&r->inner_lock);
    return out;
}

bool regex_is_hardened(const Regex *r)            { return r->hardened; }
bool regex_is_fwd_begin_anchored(const Regex *r)  { return r->fwd_begin_anchored; }
bool regex_has_fwd_prefix(const Regex *r)         { return prefix_is_some_fwd(r->prefix); }

const char *regex_prefix_kind_name(const Regex *r)
{
    if (r == nullptr || r->prefix == nullptr) return nullptr;
    switch (prefix_kind_tag(r->prefix)) {
    case PREFIX_KIND_ANCHORED_FWD:    return "AnchoredFwd";
    case PREFIX_KIND_ANCHORED_FWD_LB: return "AnchoredFwdLb";
    case PREFIX_KIND_ANCHORED_REV:    return "AnchoredRev";
    case PREFIX_KIND_POTENTIAL_START: return "PotentialStart";
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Result-finalisation helpers shared by the find_all_* dispatch arms.
// ---------------------------------------------------------------------------

static inline void finalize_result(n00b_list_t(Match) *out_full,
                                   size_t *out_count,
                                   size_t *out_total,
                                   n00b_list_t(Match) *src)
{
    size_t n = n00b_list_len(*src);
    if (out_full) {
        n00b_list_clear(*out_full);
        for (size_t i = 0; i < n; ++i) {
            n00b_list_push(*out_full, n00b_list_get(*src, i));
        }
    }
    if (out_count) *out_count = n;
    if (out_total) {
        size_t total = 0;
        for (size_t i = 0; i < n; ++i) {
            Match m = n00b_list_get(*src, i);
            total += m.end - m.start;
        }
        *out_total = total;
    }
}

// Forward decls of internal scan helpers.
static n00b_regex_engine_err_t find_all_dfa(Regex *r, const uint8_t *input,
                                             size_t len,
                                             n00b_list_t(Match) *out_full,
                                             size_t *out_count, size_t *out_total);
static n00b_regex_engine_err_t find_all_fwd_prefix(Regex *r, const uint8_t *input,
                                                    size_t len,
                                                    n00b_list_t(Match) *out_full,
                                                    size_t *out_count, size_t *out_total);
static n00b_regex_engine_err_t find_all_fwd_lb_prefix(Regex *r, const uint8_t *input,
                                                       size_t len,
                                                       n00b_list_t(Match) *out_full,
                                                       size_t *out_count,
                                                       size_t *out_total);
static n00b_regex_engine_err_t find_all_fwd_bounded(Regex *r, const uint8_t *input,
                                                     size_t len,
                                                     n00b_list_t(Match) *out_full,
                                                     size_t *out_count,
                                                     size_t *out_total);
static n00b_regex_engine_err_t is_match_fwd_bounded(Regex *r, const uint8_t *input,
                                                     size_t len, bool *out);
static n00b_regex_engine_err_t regex_find_all_inner(Regex *r, const uint8_t *input,
                                                     size_t input_len,
                                                     n00b_list_t(Match) *out_full,
                                                     size_t *out_count,
                                                     size_t *out_total);

n00b_regex_engine_err_t regex_find_all(Regex *r, const uint8_t *input,
                                        size_t input_len,
                                        n00b_list_t(Match) *out)
{
    n00b_require(out != nullptr, "regex_find_all: out must not be NULL");
    n00b_list_clear(*out);
    return regex_find_all_inner(r, input, input_len, out, nullptr, nullptr);
}

n00b_regex_engine_err_t regex_count_all(Regex *r, const uint8_t *input,
                                         size_t input_len, size_t *out_count)
{
    n00b_require(out_count != nullptr, "regex_count_all: out_count must not be NULL");
    *out_count = 0;
    return regex_find_all_inner(r, input, input_len, nullptr, out_count, nullptr);
}

n00b_regex_engine_err_t regex_total_span(Regex *r, const uint8_t *input,
                                          size_t input_len, size_t *out_total)
{
    n00b_require(out_total != nullptr, "regex_total_span: out_total must not be NULL");
    *out_total = 0;
    return regex_find_all_inner(r, input, input_len, nullptr, nullptr, out_total);
}

static n00b_regex_engine_err_t regex_find_all_inner(Regex *r, const uint8_t *input,
                                                     size_t input_len,
                                                     n00b_list_t(Match) *out_full,
                                                     size_t *out_count,
                                                     size_t *out_total)
{
    n00b_require(r != nullptr, "regex_find_all_inner: r must not be NULL");
    n00b_require(!(input == nullptr && input_len > 0),
                 "regex_find_all_inner: input must not be NULL when input_len > 0");

    if (r->is_empty_lang) return N00B_REGEX_ENGINE_ERR_NONE;
    if (input_len == 0) {
        if (r->empty_nullable) {
            if (out_full)  n00b_list_push(*out_full, ((Match){0, 0}));
            if (out_count) *out_count = 1;
        }
        return N00B_REGEX_ENGINE_ERR_NONE;
    }
    if (r->fwd_begin_anchored) {
        bool found; Match m;
        n00b_regex_engine_err_t e = regex_find_anchored(r, input, input_len, &found, &m);
        if (e != N00B_REGEX_ENGINE_ERR_NONE) return e;
        if (found) {
            if (out_full)  n00b_list_push(*out_full, m);
            if (out_count) *out_count = 1;
            if (out_total) *out_total = m.end - m.start;
        }
        return N00B_REGEX_ENGINE_ERR_NONE;
    }
    if (r->hardened) {
        if (r->has_bounded_prefix || r->has_bounded) {
            return find_all_fwd_bounded(r, input, input_len, out_full, out_count, out_total);
        }
        return find_all_dfa(r, input, input_len, out_full, out_count, out_total);
    }

    if (r->prefix) {
        switch (prefix_kind_tag(r->prefix)) {
        case PREFIX_KIND_ANCHORED_FWD:
            return find_all_fwd_prefix(r, input, input_len, out_full, out_count, out_total);
        case PREFIX_KIND_ANCHORED_FWD_LB:
            return find_all_fwd_lb_prefix(r, input, input_len, out_full, out_count, out_total);
        case PREFIX_KIND_ANCHORED_REV:
        case PREFIX_KIND_POTENTIAL_START:
            return find_all_dfa(r, input, input_len, out_full, out_count, out_total);
        }
    }
    if (r->has_bounded) {
        return find_all_fwd_bounded(r, input, input_len, out_full, out_count, out_total);
    }
    return find_all_dfa(r, input, input_len, out_full, out_count, out_total);
}

// ---------------------------------------------------------------------------
// find_anchored / is_match
// ---------------------------------------------------------------------------

n00b_regex_engine_err_t regex_find_anchored(Regex *r, const uint8_t *input,
                                             size_t input_len,
                                             bool *found, Match *out_match)
{
    n00b_require(r         != nullptr, "regex_find_anchored: r must not be NULL");
    n00b_require(found     != nullptr, "regex_find_anchored: found must not be NULL");
    n00b_require(out_match != nullptr, "regex_find_anchored: out_match must not be NULL");
    n00b_require(!(input == nullptr && input_len > 0),
                 "regex_find_anchored: input must not be NULL when input_len > 0");

    *found = false;
    if (r->is_empty_lang) return N00B_REGEX_ENGINE_ERR_NONE;
    if (input_len == 0) {
        if (r->empty_nullable) {
            *found = true;
            *out_match = (Match){0, 0};
        }
        return N00B_REGEX_ENGINE_ERR_NONE;
    }
    n00b_mutex_lock(&r->inner_lock);
    size_t max_end;
    n00b_regex_engine_err_t err = N00B_REGEX_ENGINE_ERR_NONE;
    {
        n00b_result_t(size_t) sr = engine_LDFA_scan_fwd_slow(
            r->inner->fwd, r->inner->b, 0, input, input_len);
        if (!n00b_result_is_ok(sr)) {
            err = algebra_err_to_engine(n00b_result_get_err(sr));
        } else {
            max_end = n00b_result_get(sr);
        }
    }
    n00b_mutex_unlock(&r->inner_lock);
    if (err != N00B_REGEX_ENGINE_ERR_NONE) return err;
    if (max_end != engine_NO_MATCH) {
        *found = true;
        *out_match = (Match){0, max_end};
    }
    return N00B_REGEX_ENGINE_ERR_NONE;
}

n00b_regex_engine_err_t regex_is_match(Regex *r, const uint8_t *input,
                                        size_t input_len, bool *out)
{
    n00b_require(r   != nullptr, "regex_is_match: r must not be NULL");
    n00b_require(out != nullptr, "regex_is_match: out must not be NULL");
    n00b_require(!(input == nullptr && input_len > 0),
                 "regex_is_match: input must not be NULL when input_len > 0");

    *out = false;
    if (r->is_empty_lang) return N00B_REGEX_ENGINE_ERR_NONE;
    if (input_len == 0) { *out = r->empty_nullable; return N00B_REGEX_ENGINE_ERR_NONE; }
    if (r->fwd_begin_anchored) {
        bool found; Match m;
        n00b_regex_engine_err_t e = regex_find_anchored(r, input, input_len, &found, &m);
        if (e != N00B_REGEX_ENGINE_ERR_NONE) return e;
        *out = found;
        return N00B_REGEX_ENGINE_ERR_NONE;
    }
    if (r->has_bounded) return is_match_fwd_bounded(r, input, input_len, out);

    if (r->prefix) {
        FwdPrefixSearch *fp = prefix_kind_fwd_search(r->prefix);
        if (fp) {
            n00b_mutex_lock(&r->inner_lock);
            size_t prefix_len = fwd_prefix_search_len(fp);
            size_t search_start = 0;
            for (;;) {
                size_t candidate;
                {
                    n00b_option_t(size_t) opt = fwd_prefix_search_find_fwd(
                        fp, input, input_len, search_start);
                    if (!n00b_option_is_set(opt)) break;
                    candidate = n00b_option_get(opt);
                }
                uint32_t state;
                {
                    n00b_result_t(uint32_t) wr = engine_LDFA_walk_input(
                        r->inner->fwd, r->inner->b, candidate,
                        prefix_len, input, input_len);
                    if (!n00b_result_is_ok(wr)) {
                        n00b_mutex_unlock(&r->inner_lock);
                        return algebra_err_to_engine(n00b_result_get_err(wr));
                    }
                    state = n00b_result_get(wr);
                }
                if (state != 0) {
                    size_t max_end;
                    {
                        n00b_result_t(size_t) sr = engine_LDFA_scan_fwd_from(
                            r->inner->fwd, r->inner->b, state,
                            candidate + prefix_len, input, input_len);
                        if (!n00b_result_is_ok(sr)) {
                            n00b_mutex_unlock(&r->inner_lock);
                            return algebra_err_to_engine(n00b_result_get_err(sr));
                        }
                        max_end = n00b_result_get(sr);
                    }
                    if (max_end != engine_NO_MATCH && max_end > candidate) {
                        *out = true;
                        n00b_mutex_unlock(&r->inner_lock);
                        return N00B_REGEX_ENGINE_ERR_NONE;
                    }
                }
                search_start = candidate + 1;
            }
            n00b_mutex_unlock(&r->inner_lock);
            return N00B_REGEX_ENGINE_ERR_NONE;
        }
    }

    n00b_mutex_lock(&r->inner_lock);
    if (engine_LDFA_effects_id_at(r->inner->rev_ts, (size_t)engine_DFA_INITIAL) != 0) {
        *out = true;
        n00b_mutex_unlock(&r->inner_lock);
        return N00B_REGEX_ENGINE_ERR_NONE;
    }
    n00b_list_clear(*r->inner->nulls);
    {
        n00b_result_t(int) cr_r = engine_LDFA_collect_rev_first(
            r->inner->rev_ts, r->inner->b,
            input_len - 1, input, input_len,
            r->inner->nulls);
        if (!n00b_result_is_ok(cr_r)) {
            n00b_mutex_unlock(&r->inner_lock);
            return algebra_err_to_engine(n00b_result_get_err(cr_r));
        }
    }
    *out = n00b_list_len(*r->inner->nulls) > 0;
    n00b_mutex_unlock(&r->inner_lock);
    return N00B_REGEX_ENGINE_ERR_NONE;
}

// ---------------------------------------------------------------------------
// find_all_dfa
// ---------------------------------------------------------------------------

static n00b_regex_engine_err_t find_all_nullable_slow(LDFA *fwd, RegexBuilder *b,
                                                       const uint8_t *input,
                                                       size_t len,
                                                       n00b_list_t(Match) *matches)
{
    size_t pos = 0;
    while (pos < len) {
        size_t max_end;
        {
            n00b_result_t(size_t) sr = engine_LDFA_scan_fwd_slow(
                fwd, b, pos, input, len);
            if (!n00b_result_is_ok(sr)) {
                return algebra_err_to_engine(n00b_result_get_err(sr));
            }
            max_end = n00b_result_get(sr);
        }
        if (max_end != engine_NO_MATCH && max_end > pos) {
            n00b_list_push(*matches, ((Match){pos, max_end}));
            pos = max_end;
        } else if (max_end != engine_NO_MATCH) {
            n00b_list_push(*matches, ((Match){pos, pos}));
            pos += 1;
        } else {
            pos += 1;
        }
    }
    bool end_null = engine_has_any_null(
        engine_LDFA_effects_id(fwd),
        engine_LDFA_effects(fwd),
        engine_DFA_INITIAL,
        NULLABILITY_END);
    if (end_null) n00b_list_push(*matches, ((Match){len, len}));
    return N00B_REGEX_ENGINE_ERR_NONE;
}

static n00b_regex_engine_err_t find_all_dfa(Regex *r, const uint8_t *input,
                                             size_t len,
                                             n00b_list_t(Match) *out_full,
                                             size_t *out_count, size_t *out_total)
{
    n00b_require(len > 0, "find_all_dfa: len must be > 0");
    n00b_mutex_lock(&r->inner_lock);
    n00b_list_clear(*r->inner->nulls);
    n00b_list_clear(*r->inner->matches);

    if ((r->always_nullable || r->rev_trivial) && !r->hardened) {
        n00b_regex_engine_err_t e = find_all_nullable_slow(r->inner->fwd, r->inner->b,
                                                            input, len,
                                                            r->inner->matches);
        if (e != N00B_REGEX_ENGINE_ERR_NONE) {
            n00b_mutex_unlock(&r->inner_lock); return e;
        }
        finalize_result(out_full, out_count, out_total, r->inner->matches);
        n00b_mutex_unlock(&r->inner_lock);
        return N00B_REGEX_ENGINE_ERR_NONE;
    }

    if (nullability_has(r->initial_nullability, NULLABILITY_END)) {
        n00b_list_push(*r->inner->nulls, len);
    }
    {
        n00b_result_t(int) cr_r = engine_LDFA_collect_rev(
            r->inner->rev_ts, r->inner->b, len - 1,
            input, len, r->inner->nulls);
        if (!n00b_result_is_ok(cr_r)) {
            n00b_mutex_unlock(&r->inner_lock);
            return algebra_err_to_engine(n00b_result_get_err(cr_r));
        }
    }

    // FAS hardened path
    if (r->hardened) {
        if (r->always_nullable) {
            {
                n00b_result_t(int) sr = engine_LDFA_scan_fwd_active_set_true(
                    r->inner->fwd, r->inner->b, r->inner->fas, input, len,
                    r->inner->nulls, r->inner->matches);
                if (!n00b_result_is_ok(sr)) {
                    n00b_mutex_unlock(&r->inner_lock);
                    return algebra_err_to_engine(n00b_result_get_err(sr));
                }
            }
            // Append final empty match if not already present.
            bool need = true;
            size_t mlen = n00b_list_len(*r->inner->matches);
            if (mlen > 0) {
                Match last = n00b_list_get(*r->inner->matches, mlen - 1);
                if (last.start == len) need = false;
            }
            if (need) n00b_list_push(*r->inner->matches, ((Match){len, len}));
        } else {
            n00b_result_t(int) sr = engine_LDFA_scan_fwd_active_set_false(
                r->inner->fwd, r->inner->b, r->inner->fas, input, len,
                r->inner->nulls, r->inner->matches);
            if (!n00b_result_is_ok(sr)) {
                n00b_mutex_unlock(&r->inner_lock);
                return algebra_err_to_engine(n00b_result_get_err(sr));
            }
        }
        finalize_result(out_full, out_count, out_total, r->inner->matches);
        n00b_mutex_unlock(&r->inner_lock);
        return N00B_REGEX_ENGINE_ERR_NONE;
    }

    if (r->has_fixed_length) {
        size_t fl = (size_t)r->fixed_length;
        size_t last_end = 0;
        size_t nlen = n00b_list_len(*r->inner->nulls);
        for (size_t i = nlen; i-- > 0; ) {
            size_t start = n00b_list_get(*r->inner->nulls, i);
            if (start >= last_end && start + fl <= len) {
                n00b_list_push(*r->inner->matches, ((Match){start, start + fl}));
                last_end = start + fl;
            }
        }
    } else {
        n00b_result_t(int) sr = engine_LDFA_scan_fwd_all(
            r->inner->fwd, r->inner->b, r->inner->nulls,
            input, len, r->inner->matches);
        if (!n00b_result_is_ok(sr)) {
            n00b_mutex_unlock(&r->inner_lock);
            return algebra_err_to_engine(n00b_result_get_err(sr));
        }
    }

    if (r->always_nullable) {
        n00b_list_push(*r->inner->matches, ((Match){len, len}));
    }

    finalize_result(out_full, out_count, out_total, r->inner->matches);
    n00b_mutex_unlock(&r->inner_lock);
    return N00B_REGEX_ENGINE_ERR_NONE;
}

// ---------------------------------------------------------------------------
// find_all_fwd_bounded / is_match_fwd_bounded
// ---------------------------------------------------------------------------

static n00b_regex_engine_err_t find_all_fwd_bounded(Regex *r, const uint8_t *input,
                                                     size_t len,
                                                     n00b_list_t(Match) *out_full,
                                                     size_t *out_count,
                                                     size_t *out_total)
{
    n00b_mutex_lock(&r->inner_lock);
    BDFA *bounded = r->inner->bounded;
    n00b_list_clear(*r->inner->matches);
    n00b_regex_engine_err_t e = N00B_REGEX_ENGINE_ERR_NONE;
    uint8_t scan_mode = PREFIX_NONE;
    if (bdfa_prefix_is_some(bounded)) {
        scan_mode = bdfa_prefix_is_literal(bounded) ? PREFIX_LITERAL
                                                    : PREFIX_SEARCH;
    }
    {
        n00b_result_t(bool) sr = bdfa_scan(scan_mode, false, bounded,
                                           r->inner->b, input, len,
                                           r->inner->matches);
        if (!n00b_result_is_ok(sr)) {
            e = algebra_err_to_engine(n00b_result_get_err(sr));
        }
    }
    if (e != N00B_REGEX_ENGINE_ERR_NONE) {
        n00b_mutex_unlock(&r->inner_lock); return e;
    }
    finalize_result(out_full, out_count, out_total, r->inner->matches);
    n00b_mutex_unlock(&r->inner_lock);
    return N00B_REGEX_ENGINE_ERR_NONE;
}

static n00b_regex_engine_err_t is_match_fwd_bounded(Regex *r, const uint8_t *input,
                                                     size_t len, bool *out)
{
    n00b_mutex_lock(&r->inner_lock);
    BDFA *bounded = r->inner->bounded;
    n00b_list_clear(*r->inner->matches);
    n00b_regex_engine_err_t e = N00B_REGEX_ENGINE_ERR_NONE;
    uint8_t scan_mode = PREFIX_NONE;
    if (bdfa_prefix_is_some(bounded)) {
        scan_mode = bdfa_prefix_is_literal(bounded) ? PREFIX_LITERAL
                                                    : PREFIX_SEARCH;
    }
    {
        n00b_result_t(bool) sr = bdfa_scan(scan_mode, true, bounded,
                                           r->inner->b, input, len,
                                           r->inner->matches);
        if (!n00b_result_is_ok(sr)) {
            e = algebra_err_to_engine(n00b_result_get_err(sr));
        }
        else if (out) {
            *out = n00b_result_get(sr);
        }
    }
    n00b_mutex_unlock(&r->inner_lock);
    return e;
}

// ---------------------------------------------------------------------------
// find_all_fwd_prefix
// ---------------------------------------------------------------------------

static n00b_regex_engine_err_t find_all_fwd_prefix(Regex *r, const uint8_t *input,
                                                    size_t len,
                                                    n00b_list_t(Match) *out_full,
                                                    size_t *out_count,
                                                    size_t *out_total)
{
    if (len == 0) {
        if (out_full)  n00b_list_clear(*out_full);
        if (out_count) *out_count = 0;
        if (out_total) *out_total = 0;
        return N00B_REGEX_ENGINE_ERR_NONE;
    }
    FwdPrefixSearch *fp = prefix_kind_fwd_search(r->prefix);
    n00b_require(fp != nullptr, "find_all_fwd_prefix: PrefixKind lacks FwdSearch");
    n00b_mutex_lock(&r->inner_lock);
    n00b_list_t(Match) *matches = r->inner->matches;
    n00b_list_clear(*matches);
    size_t search_start = 0;

    bool literal_path = false;
    if (r->has_fixed_length
        && r->fixed_length == (uint32_t)fwd_prefix_search_len(fp)
        && !r->has_anchors)
    {
        // Count / total-span fast path for the fixed-length literal case:
        // when the caller doesn't need the actual match list, iterate the
        // single-match SIMD entry point and count.  The all-matches SIMD
        // path allocates a fresh n00b_simd_MatchVec per call and grows it
        // geometrically.  Skipping the match list when it'll be discarded
        // is a real perf win regardless of GC, and avoids the allocation
        // pressure that triggers a known release-only LTO/O3 interaction
        // in n00b's STW (heap pointers register-promoted past the stack
        // scan in worker threads waiting on conduit IO CVs).
        if (out_full == nullptr) {
            // Count / total-span fast path for the fixed-length literal
            // case: when the caller doesn't need the actual match list,
            // iterate the single-match SIMD entry point and count.  The
            // all-matches SIMD path allocates a fresh n00b_simd_MatchVec
            // per call and grows it geometrically — pure overhead when
            // the caller is going to discard the list.
            size_t mlen  = (size_t)r->fixed_length;
            size_t count = 0;
            size_t span  = 0;
            size_t pos   = 0;
            for (;;) {
                n00b_option_t(size_t) m
                    = fwd_prefix_search_find_fwd(fp, input, len, pos);
                if (!n00b_option_is_set(m)) break;
                size_t start = n00b_option_get(m);
                count++;
                span += mlen;
                pos = start + mlen;
                if (pos > len) break;
            }
            if (out_count) *out_count = count;
            if (out_total) *out_total = span;
            n00b_mutex_unlock(&r->inner_lock);
            return N00B_REGEX_ENGINE_ERR_NONE;
        }
        literal_path = fwd_prefix_search_find_all_literal(fp, input, len, matches);
    }

    if (!literal_path) {
        // pos 0 with \A anchors
        const uint8_t  *mt_lookup   = engine_LDFA_mt_lookup(r->inner->fwd);
        const uint16_t *begin_table = engine_LDFA_begin_table(r->inner->fwd);
        uint8_t  mt    = mt_lookup[input[0]];
        uint32_t state = (uint32_t)begin_table[mt];
        if (state != (uint32_t)engine_LDFA_pruned(r->inner->fwd)) {
            size_t max_end;
            {
                n00b_result_t(size_t) sr = engine_LDFA_scan_fwd_from(
                    r->inner->fwd, r->inner->b, state,
                    1, input, len);
                if (!n00b_result_is_ok(sr)) {
                    n00b_mutex_unlock(&r->inner_lock);
                    return algebra_err_to_engine(n00b_result_get_err(sr));
                }
                max_end = n00b_result_get(sr);
            }
            if (max_end != engine_NO_MATCH && max_end > 0) {
                n00b_list_push(*matches, ((Match){0, max_end}));
                search_start = max_end;
            }
        }
        size_t prefix_len = fwd_prefix_search_len(fp);
        for (;;) {
            n00b_option_t(size_t) fr = fwd_prefix_search_find_fwd(fp, input, len,
                                                                   search_start);
            if (!n00b_option_is_set(fr)) break;
            size_t candidate = n00b_option_get(fr);

            uint32_t state2;
            {
                n00b_result_t(uint32_t) wr = engine_LDFA_walk_input(
                    r->inner->fwd, r->inner->b, candidate,
                    prefix_len, input, len);
                if (!n00b_result_is_ok(wr)) {
                    n00b_mutex_unlock(&r->inner_lock);
                    return algebra_err_to_engine(n00b_result_get_err(wr));
                }
                state2 = n00b_result_get(wr);
            }
            if (state2 != 0) {
                size_t max_end;
                {
                    n00b_result_t(size_t) sr = engine_LDFA_scan_fwd_from(
                        r->inner->fwd, r->inner->b, state2,
                        candidate + prefix_len, input, len);
                    if (!n00b_result_is_ok(sr)) {
                        n00b_mutex_unlock(&r->inner_lock);
                        return algebra_err_to_engine(n00b_result_get_err(sr));
                    }
                    max_end = n00b_result_get(sr);
                }
                if (max_end != engine_NO_MATCH && max_end > candidate) {
                    n00b_list_push(*matches, ((Match){candidate, max_end}));
                    search_start = max_end;
                    continue;
                }
            }
            search_start = candidate + 1;
        }
    }

    finalize_result(out_full, out_count, out_total, matches);
    n00b_mutex_unlock(&r->inner_lock);
    return N00B_REGEX_ENGINE_ERR_NONE;
}

// ---------------------------------------------------------------------------
// find_all_fwd_lb_prefix
// ---------------------------------------------------------------------------

static n00b_regex_engine_err_t find_all_fwd_lb_prefix(Regex *r, const uint8_t *input,
                                                       size_t len,
                                                       n00b_list_t(Match) *out_full,
                                                       size_t *out_count,
                                                       size_t *out_total)
{
    FwdPrefixSearch *fp = prefix_kind_fwd_search(r->prefix);
    n00b_require(fp != nullptr, "find_all_fwd_lb_prefix: PrefixKind lacks FwdSearch");
    n00b_mutex_lock(&r->inner_lock);
    n00b_list_clear(*r->inner->matches);
    size_t lb_len = (size_t)r->lb_check_bytes;
    size_t search_start = 0;

    if (r->fwd_lb_begin_nullable && len > 0) {
        size_t max_end;
        {
            n00b_result_t(size_t) sr = engine_LDFA_scan_fwd_slow(
                r->inner->fwd, r->inner->b, 0, input, len);
            if (!n00b_result_is_ok(sr)) {
                n00b_mutex_unlock(&r->inner_lock);
                return algebra_err_to_engine(n00b_result_get_err(sr));
            }
            max_end = n00b_result_get(sr);
        }
        if (max_end != engine_NO_MATCH) {
            n00b_list_push(*r->inner->matches, ((Match){0, max_end}));
            search_start = (max_end == 0) ? 1 : max_end;
        }
    }

    for (;;) {
        n00b_option_t(size_t) fr = fwd_prefix_search_find_fwd(fp, input, len,
                                                               search_start);
        if (!n00b_option_is_set(fr)) break;
        size_t candidate = n00b_option_get(fr);

        size_t body_start = candidate + lb_len;
        size_t max_end;
        {
            n00b_result_t(size_t) sr = engine_LDFA_scan_fwd_from(
                r->inner->fwd, r->inner->b,
                engine_DFA_INITIAL, body_start, input, len);
            if (!n00b_result_is_ok(sr)) {
                n00b_mutex_unlock(&r->inner_lock);
                return algebra_err_to_engine(n00b_result_get_err(sr));
            }
            max_end = n00b_result_get(sr);
        }
        if (max_end != engine_NO_MATCH) {
            n00b_list_push(*r->inner->matches, ((Match){body_start, max_end}));
            search_start = max_end;
        } else {
            search_start = body_start;
        }
    }

    finalize_result(out_full, out_count, out_total, r->inner->matches);
    n00b_mutex_unlock(&r->inner_lock);
    return N00B_REGEX_ENGINE_ERR_NONE;
}

// ---------------------------------------------------------------------------
// matches_push — fas.c calls this to push (start, end) onto a void *matches.
// The void* is always a `n00b_list_t(Match) *`.
// ---------------------------------------------------------------------------

void matches_push(void *matches, size_t start, size_t end)
{
    n00b_list_t(Match) *m = (n00b_list_t(Match) *)matches;
    n00b_list_push(*m, ((Match){.start = start, .end = end}));
}
