/**
 * @file algebra.h
 * @brief Boolean-algebra regex builder: nodes, transitions, derivatives.
 *
 * Internal regex-engine header, not part of the public n00b surface.
 * Algorithmic names track upstream Rust closely and intentionally do
 * not carry the `n00b_` prefix — the lowercase-snake `regex_builder_*`
 * naming mirrors Rust's `RegexBuilder` impl.
 *
 * The `RegexBuilder` owns the canonical hash-consed AST/DAG of regex
 * nodes plus the symbolic transition-set graph (`TRegex`) used by the
 * derivative engine.  All structural builders (`mk_pred`, `mk_concat`,
 * `mk_union`, `mk_inter`, `mk_star`, `mk_lookahead`, `mk_lookbehind`,
 * `mk_counted`, …) intern through the builder so equal sub-trees share
 * a single `NodeId`.
 *
 * Companion source: `src/text/regex/algebra/algebra.c`.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "adt/result.h"
#include "core/alloc.h"
#include "internal/regex/ids.h"

// ---------------------------------------------------------------------------
// Algebra-local single-byte newtypes shared across the engine.
// ---------------------------------------------------------------------------

/** @brief Three-bit flag set encoding regex nullability classes. */
typedef struct Nullability { uint8_t v; } Nullability;

/** @brief Eight-bit flag set: nullability + presence-of-feature bits. */
typedef struct MetaFlags   { uint8_t v; } MetaFlags;

/** @brief Two-bit cache state for the `is-empty-language` lookup. */
typedef struct NodeFlags   { uint8_t v; } NodeFlags;

// ---------------------------------------------------------------------------
// Kind enum — numeric values are observable across crates (engine,
// parser, prefix extractor) so the layout is fixed here.
// ---------------------------------------------------------------------------

/** @brief Discriminator tag for every node kind in the algebra DAG. */
typedef enum : uint8_t {
    KIND_PRED = 0,
    KIND_STAR,
    KIND_BEGIN,
    KIND_END,
    KIND_CONCAT,
    KIND_UNION,
    KIND_COMPL,
    KIND_LOOKBEHIND,
    KIND_LOOKAHEAD,
    KIND_INTER,
    KIND_COUNTED,
} Kind;

// ---------------------------------------------------------------------------
// Opaque builder.
// ---------------------------------------------------------------------------

/**
 * @brief Hash-consing builder for the regex algebra.
 *
 * Owns the node array, the node-key intern map, the metadata builder
 * (flags + nullability sets), the transition-regex graph, the
 * symbolic-derivative caches, and the reverse / prune memos.  All
 * fields are private; all access goes through the `regex_builder_*`
 * functions declared below.
 */
typedef struct RegexBuilder RegexBuilder;

/**
 * @brief Allocate and initialise a fresh `RegexBuilder`.
 *
 * Pre-interns the well-known sentinel ids exposed via `NODE_ID_*`
 * below in fixed order: MISSING, BOT, EPS, TOP, TOPSTAR (`TS`),
 * TOPPLUS, BEGIN, END.
 *
 * @param allocator  Per-regex pool allocator (or nullptr for the
 *                   runtime default).  When non-null, every
 *                   allocation the builder makes — including its
 *                   embedded MetadataBuilder / Solver / NullsBuilder —
 *                   targets this allocator.  Used to route a compile
 *                   through a per-regex pool so the GC never fires
 *                   during compile (gc-bits.md Step 5).
 */
[[nodiscard]] RegexBuilder *regex_builder_new(n00b_allocator_t *allocator);

/**
 * @brief Drop the builder and every owned subsystem.  Safe with @p self == nullptr.
 */
void                        regex_builder_free(RegexBuilder *self);

/** @brief Get the node kind for @p node_id. */
[[nodiscard]] Kind regex_builder_get_kind(const RegexBuilder *self, NodeId node_id);

// ---------------------------------------------------------------------------
// Well-known sentinel NodeIds.  Values fixed by `regex_builder_new()`'s
// init order; defined with external linkage in algebra.c.
// ---------------------------------------------------------------------------

extern const NodeId NODE_ID_MISSING;
extern const NodeId NODE_ID_BOT;
extern const NodeId NODE_ID_EPS;
extern const NodeId NODE_ID_TOP;
extern const NodeId NODE_ID_TS;
extern const NodeId NODE_ID_TOPPLUS;
extern const NodeId NODE_ID_BEGIN;
extern const NodeId NODE_ID_END;

// ---------------------------------------------------------------------------
// Error codes returned by fallible algebra operations.  Cast to `int`
// at API boundaries that funnel through `n00b_result_t.err`.
// ---------------------------------------------------------------------------

/** @brief Domain-specific return code for fallible algebra operations.
 *
 * Stored as the `int` err side of `n00b_result_t(T)` per § 7.5 mapping
 * (D14 int-err idiom).  Cast to `int` at result construction;
 * `n00b_regex_algebra_err_str` casts back internally.
 */
typedef enum n00b_regex_algebra_err_t {
    N00B_REGEX_ALGEBRA_ERR_NONE = 0,
    N00B_REGEX_ALGEBRA_ERR_ANCHOR_LIMIT,
    N00B_REGEX_ALGEBRA_ERR_STATE_SPACE_EXPLOSION,
    N00B_REGEX_ALGEBRA_ERR_UNSUPPORTED_PATTERN,
} n00b_regex_algebra_err_t;

/** @brief Static human-readable description for an algebra err kind. */
[[nodiscard]] const char *n00b_regex_algebra_err_str(int kind);

// ---------------------------------------------------------------------------
// Node-builder API (the "mk_" family).
// ---------------------------------------------------------------------------

NodeId regex_builder_mk_pred(RegexBuilder *self, TSetId pred);
NodeId regex_builder_mk_pred_not(RegexBuilder *self, TSetId set);
NodeId regex_builder_mk_u8(RegexBuilder *self, uint8_t c);
NodeId regex_builder_mk_range_u8(RegexBuilder *self, uint8_t start, uint8_t end_inclusive);

/**
 * @brief A `[lo, hi]` byte range (both endpoints inclusive).  Used by
 *        `regex_builder_mk_ranges_u8` (below) and the algebra-side
 *        unicode_classes builders in `internal/regex/unicode_classes_classes.h`.
 */
typedef struct range_u8 {
    uint8_t lo;
    uint8_t hi;
} range_u8_t;

/**
 * @brief Build the union of @p n byte ranges.  Equivalent to a sequence of
 *        `regex_builder_mk_range_u8` calls combined via `regex_builder_mk_union`.
 */
NodeId regex_builder_mk_ranges_u8(RegexBuilder *self, const range_u8_t *ranges, size_t n);

NodeId regex_builder_mk_concat(RegexBuilder *self, NodeId head, NodeId tail);
NodeId regex_builder_mk_union(RegexBuilder *self, NodeId left, NodeId right);
NodeId regex_builder_mk_inter(RegexBuilder *self, NodeId a, NodeId b);
NodeId regex_builder_mk_star(RegexBuilder *self, NodeId body);
NodeId regex_builder_mk_plus(RegexBuilder *self, NodeId body);
NodeId regex_builder_mk_opt(RegexBuilder *self, NodeId body);
NodeId regex_builder_mk_repeat(RegexBuilder *self, NodeId body, uint32_t lower, uint32_t upper);
NodeId regex_builder_mk_compl(RegexBuilder *self, NodeId body);
NodeId regex_builder_mk_lookahead(RegexBuilder *self, NodeId body, NodeId tail, uint32_t rel);
NodeId regex_builder_mk_lookbehind(RegexBuilder *self, NodeId body, NodeId prev);
NodeId regex_builder_mk_neg_lookahead(RegexBuilder *self, NodeId body, uint32_t rel);
NodeId regex_builder_mk_neg_lookbehind(RegexBuilder *self, NodeId body);
NodeId regex_builder_mk_counted(RegexBuilder *self, NodeId body, NodeId chain, uint32_t packed);
NodeId regex_builder_mk_string(RegexBuilder *self, const char *raw);
NodeId regex_builder_mk_bytestring(RegexBuilder *self, const uint8_t *raw, size_t n);
NodeId regex_builder_mk_begins_with(RegexBuilder *self, NodeId n);
NodeId regex_builder_mk_not_begins_with(RegexBuilder *self, NodeId n);

NodeId regex_builder_mk_unions(RegexBuilder *self, const NodeId *nodes, size_t n);
NodeId regex_builder_mk_inters(RegexBuilder *self, const NodeId *nodes, size_t n);
NodeId regex_builder_mk_concats(RegexBuilder *self, const NodeId *nodes, size_t n);

// ---------------------------------------------------------------------------
// Queries.
// ---------------------------------------------------------------------------

uint32_t    regex_builder_num_nodes(const RegexBuilder *self);
size_t      regex_builder_tree_size(const RegexBuilder *self, NodeId root, size_t limit);
Nullability regex_builder_nullability(const RegexBuilder *self, NodeId node_id);
Nullability regex_builder_nullability_emptystring(const RegexBuilder *self, NodeId node_id);
bool        regex_builder_is_always_nullable(const RegexBuilder *self, NodeId node_id);
bool        regex_builder_any_nonbegin_nullable(const RegexBuilder *self, NodeId node_id);
bool        regex_builder_contains_look(const RegexBuilder *self, NodeId node_id);
bool        regex_builder_contains_anchors(const RegexBuilder *self, NodeId node_id);
bool        regex_builder_contains_lookbehind(NodeId n, RegexBuilder *self);
bool        regex_builder_is_infinite(const RegexBuilder *self, NodeId node_id);
bool        regex_builder_is_nullable(RegexBuilder *self, NodeId node_id, Nullability mask);
bool        regex_builder_starts_with_ts(const RegexBuilder *self, NodeId node_id);
bool        regex_builder_ends_with_ts(const RegexBuilder *self, NodeId node_id);
bool        regex_builder_ends_with_ts_any_branch(const RegexBuilder *self, NodeId node_id);

/** @brief (min, max) length bounds; max == UINT32_MAX means unbounded. */
typedef struct MinMax { uint32_t min; uint32_t max; } MinMax;

MinMax regex_builder_get_min_max_length(const RegexBuilder *self, NodeId node_id);

/** @brief Returns true and writes the exact length to @p *out if fixed-length. */
bool   regex_builder_get_fixed_length(const RegexBuilder *self, NodeId node_id, uint32_t *out);

// ---------------------------------------------------------------------------
// Field accessors / readonly walkers (used by sibling subsystems).
// ---------------------------------------------------------------------------

NodeId      regex_builder_get_left(const RegexBuilder *self, NodeId node_id);
NodeId      regex_builder_get_right(const RegexBuilder *self, NodeId node_id);
uint32_t    regex_builder_get_extra(const RegexBuilder *self, NodeId node_id);
NodeId      regex_builder_get_lookahead_inner(const RegexBuilder *self, NodeId nid);
NodeId      regex_builder_get_lookahead_tail(const RegexBuilder *self, NodeId nid);
uint32_t    regex_builder_get_lookahead_rel(const RegexBuilder *self, NodeId nid);
NodeId      regex_builder_get_lookbehind_inner(const RegexBuilder *self, NodeId nid);
NodeId      regex_builder_get_lookbehind_prev(const RegexBuilder *self, NodeId nid);
TSetId      regex_builder_pred_tset(const RegexBuilder *self, NodeId node_id);
MetaFlags   regex_builder_get_meta_flags(const RegexBuilder *self, NodeId node_id);
MetaFlags   regex_builder_get_flags_contains(const RegexBuilder *self, NodeId node_id);
Nullability regex_builder_get_only_nullability(const RegexBuilder *self, NodeId node_id);
NullsId     regex_builder_get_nulls_id(const RegexBuilder *self, NodeId node_id);
NullsId     regex_builder_get_nulls_id_w_mask(RegexBuilder *self, NodeId node_id, Nullability mask);
NullsId     regex_builder_center_nulls_id(RegexBuilder *self, NullsId nid);

NodeId      regex_builder_left(const RegexBuilder *b, NodeId n);
NodeId      regex_builder_right(const RegexBuilder *b, NodeId n);
NodeId      regex_builder_node_left(RegexBuilder *b, NodeId n);
NodeId      regex_builder_node_right(RegexBuilder *b, NodeId n);

void        regex_builder_set_lookahead_context_max(RegexBuilder *self, uint32_t v);

// ---------------------------------------------------------------------------
// Transforms.
// ---------------------------------------------------------------------------

n00b_result_t(NodeId) regex_builder_strip_lb(RegexBuilder *self, NodeId node_id);
n00b_result_t(NodeId) regex_builder_normalize_rev(RegexBuilder *self, NodeId node_id);
n00b_result_t(NodeId) regex_builder_ts_rev_start(RegexBuilder *self, NodeId node_id);
NodeId                regex_builder_nonbegins(RegexBuilder *self, NodeId node_id);
NodeId                regex_builder_strip_prefix_safe(RegexBuilder *self, NodeId node_id);

/**
 * @brief Symbolic Brzozowski derivative.
 * @return `n00b_result_t(TRegexId)` — ok value carries the derivative class id;
 *         err carries an `n00b_regex_algebra_err_t` value cast to int.
 */
n00b_result_t(TRegexId) regex_builder_der(RegexBuilder *self, NodeId node_id,
                                          Nullability mask);

n00b_result_t(NodeId) regex_builder_reverse(RegexBuilder *self, NodeId node_id);

// ---------------------------------------------------------------------------
// (NodeId, TSetId) target produced by `regex_builder_collect_der_targets`.
// ---------------------------------------------------------------------------

/** @brief Single (target node, path predicate) record. */
typedef struct DerTarget    { NodeId target; TSetId path; } DerTarget;

/** @brief Caller-managed growable array of `DerTarget`. */
typedef struct VecDerTarget { DerTarget *data; size_t len; size_t cap; } VecDerTarget;

/**
 * @brief Walk a `TRegex` and accumulate (target, path) leaves into @p *out.
 *
 * The caller is responsible for zero-initialising @p *out and for freeing
 * `out->data` (allocated via the n00b allocator).  Path bits are AND/OR-merged
 * via the solver across ITE branches.
 */
void regex_builder_collect_der_targets(RegexBuilder *self, TRegexId der,
                                       TSetId path_set, VecDerTarget *out);

// ---------------------------------------------------------------------------
// iter_sat: walk a TRegex saturating set; stack is a growable Vec<(TRegexId,
// TSetId)> seeded by the caller.  Callback receives ctx FIRST.
// ---------------------------------------------------------------------------

/** @brief One frame of the iter_sat traversal stack. */
typedef struct {
    TRegexId id;
    TSetId   set;
} IterSatFrame;

/** @brief Caller-managed growable stack of `IterSatFrame`. */
typedef struct {
    IterSatFrame *data;
    size_t        len;
    size_t        cap;
} IterSatStack;

void iter_sat_stack_init(IterSatStack *s);
void iter_sat_stack_push(IterSatStack *s, IterSatFrame f,
                         n00b_allocator_t *allocator);
void iter_sat_stack_free(IterSatStack *s);

void regex_builder_iter_sat(RegexBuilder *self, IterSatStack *stack,
                            void *ctx,
                            void (*f)(void *, RegexBuilder *,
                                      NodeId, TSetId));

// ---------------------------------------------------------------------------
// Pruning / simplification.
// ---------------------------------------------------------------------------

NodeId regex_builder_prune_begin(RegexBuilder *self, NodeId node_id);
NodeId regex_builder_prune_begin_eps(RegexBuilder *self, NodeId node_id);
NodeId regex_builder_simplify_fwd_initial(RegexBuilder *self, NodeId node_id);
NodeId regex_builder_simplify_rev_initial(RegexBuilder *self, NodeId node_id);

/**
 * @brief FxHashMap<NodeId, NodeId> shape memo passed to prune_fwd / prune_rev
 *        so shared sub-DAG nodes are pruned exactly once.
 *
 * Opaque to consumers; allocate via `regex_builder_prune_memo_new` and free
 * via `regex_builder_prune_memo_free`.
 */
typedef struct NodeIdMap NodeIdMap;

[[nodiscard]] NodeIdMap *regex_builder_prune_memo_new(n00b_allocator_t *allocator);
void                     regex_builder_prune_memo_free(NodeIdMap *memo);
NodeId                   regex_builder_prune_fwd(RegexBuilder *self, NodeId node_id, NodeIdMap *memo);
NodeId                   regex_builder_prune_rev(RegexBuilder *self, NodeId node_id, NodeIdMap *memo);

NodeId regex_builder_try_elim_lookarounds(RegexBuilder *self, NodeId node_id);
NodeId regex_builder_mk_non_nullable_safe(RegexBuilder *self, NodeId node);
NodeId regex_builder_extract_nulls_mask(RegexBuilder *self, NodeId body, Nullability mask);

// ---------------------------------------------------------------------------
// Subsumption / emptiness.
// ---------------------------------------------------------------------------

bool regex_builder_is_empty_lang(RegexBuilder *self, NodeId node, bool *out_known, bool *out_empty);
bool regex_builder_subsumes_known(RegexBuilder *self, NodeId larger_lang,
                                  NodeId smaller_lang,
                                  bool *out_known, bool *out_subsumes);

// ---------------------------------------------------------------------------
// Pretty-printing (NUL-terminated heap `char *`, GC-managed).
// ---------------------------------------------------------------------------

[[nodiscard]] char *regex_builder_pp(const RegexBuilder *self, NodeId node_id);
[[nodiscard]] char *regex_builder_ppt_str(const RegexBuilder *self, TRegexId term_id);

// ---------------------------------------------------------------------------
// Literal-prefix extraction.
// ---------------------------------------------------------------------------

/** @brief Optional literal-byte prefix recovered from a node's language. */
typedef struct LiteralPrefix {
    uint8_t *data;
    size_t   len;
} LiteralPrefix;

LiteralPrefix regex_builder_extract_literal_prefix(const RegexBuilder *self, NodeId node);

/**
 * @brief Longest literal byte run every word of a node's language contains.
 *
 * Unlike the prefix extraction, a run that does not start at the beginning
 * still counts: elements of the concat spine that are not single bytes end the
 * current run and are stepped over. Every run is trimmed to whole UTF-8
 * characters before the longest is chosen, so a class over a multi-byte
 * character cannot leave half of one on the end of the answer.
 */
LiteralPrefix regex_builder_extract_required_literal(const RegexBuilder *self, NodeId node);

// ---------------------------------------------------------------------------
// Solver / nulls escape hatches used by sibling regex TUs.
// ---------------------------------------------------------------------------

struct Solver;
struct NullsBuilder;
struct NullState;
typedef struct Solver       Solver;
typedef struct NullsBuilder NullsBuilder;
typedef struct NullState    NullState;

[[nodiscard]] const Solver *regex_builder_solver_ref(const RegexBuilder *self);
[[nodiscard]] Solver       *regex_builder_solver(RegexBuilder *self);

/**
 * @brief Return the per-builder allocator, or nullptr if the builder
 *        was constructed without one (runtime-default allocation).
 *        Engine TUs use this to forward the per-regex pool allocator
 *        to allocations they make on behalf of the builder.
 */
[[nodiscard]] n00b_allocator_t *regex_builder_allocator(const RegexBuilder *self);

size_t regex_builder_nulls_count(const RegexBuilder *self);
size_t regex_builder_nulls_entry_vec(const RegexBuilder *self, uint32_t id,
                                     NullState *out, size_t cap);

// ---------------------------------------------------------------------------
// Internal NodeKey accessor used by sibling regex TUs (engine.c, prefix.c).
// `regex_builder_get_node` returns a borrowed read-only pointer into the
// builder's node array — the pointer is invalidated by any mutating op
// that grows the array.
// ---------------------------------------------------------------------------

/**
 * @brief Hash-cons key uniquely identifying a node in the builder.
 *
 * The {kind, left, right, extra} tuple is the canonical content
 * identity used for interning.  `extra` carries kind-specific
 * payload — pred TSetId, lookahead `rel`, counted packed (best, step).
 */
typedef struct NodeKey {
    Kind     kind;
    NodeId   left;
    NodeId   right;
    uint32_t extra;
} NodeKey;

[[nodiscard]] const NodeKey *regex_builder_get_node(const RegexBuilder *self, NodeId nid);

// ---------------------------------------------------------------------------
// Linearised tree walkers (used by union/inter rewrites in algebra and
// engine).  Mirrors Rust's `iter_unions` / `iter_inters` impls.
// ---------------------------------------------------------------------------

void regex_builder_iter_union(RegexBuilder *self, NodeId u, void *ctx,
                              void (*visit)(void *, RegexBuilder *, NodeId));
void regex_builder_iter_inter(RegexBuilder *self, NodeId head, void *ctx,
                              void (*visit)(void *, RegexBuilder *, NodeId));
void regex_builder_iter_union_while(RegexBuilder *self, NodeId rhs,
                                    void *visitor_ctx,
                                    bool (*visitor)(void *, RegexBuilder *, NodeId));
void regex_builder_iter_unions_b(RegexBuilder *self, NodeId u, void *ctx,
                                 void (*f)(void *, RegexBuilder *, NodeId));

// ---------------------------------------------------------------------------
// MetadataId helpers — `MetadataId` itself comes from `ids.h`; the
// metadata struct is private to algebra.c, but engine.c needs to know
// the id of a node's metadata for table-dump diagnostics.
// ---------------------------------------------------------------------------

MetadataId regex_builder_get_node_meta_id(RegexBuilder *self, NodeId n);

// ---------------------------------------------------------------------------
// Cross-crate misc.
// ---------------------------------------------------------------------------

/** @brief qsort comparator for `NodeId` arrays. */
int  nodeid_cmp(const void *pa, const void *pb);

/** @brief Lower-snake `tset_contains_byte` alias used by SIMD code. */
bool tset_contains_byte(const TSet *self, uint8_t b);

/** @brief Helper used by codegen: returns `n + 1` saturating at `UINT32_MAX`. */
uint32_t helpers_incr_rel(uint32_t n);

// ---------------------------------------------------------------------------
// NodeFlags accessors (engine cache_empty consumers).
// ---------------------------------------------------------------------------

bool node_flags_is_checked(NodeFlags f);
bool node_flags_is_empty(NodeFlags f);
bool nodeflags_is_checked(NodeFlags f);
bool nodeflags_is_empty(NodeFlags f);

// MetaFlags helpers exposed for inter-TU use.
[[nodiscard]] Nullability metaflags_nullability(MetaFlags self);
[[nodiscard]] MetaFlags   metaflags_with_nullability(Nullability n, MetaFlags flags);
[[nodiscard]] bool        metaflags_has(MetaFlags self, MetaFlags flag);
[[nodiscard]] MetaFlags   metaflags_and(MetaFlags self, MetaFlags other);
[[nodiscard]] MetaFlags   metaflags_or(MetaFlags self, MetaFlags other);
[[nodiscard]] bool        metaflags_contains_inter(MetaFlags self);
[[nodiscard]] MetaFlags   metaflags_all_contains_flags(MetaFlags self);

// MetaFlags constants used by sibling TUs.
extern const MetaFlags METAFLAGS_ZERO;
extern const MetaFlags METAFLAGS_INFINITE_LENGTH;
extern const MetaFlags METAFLAGS_CONTAINS_INTER;
extern const MetaFlags METAFLAGS_CONTAINS_ANCHORS;
extern const MetaFlags METAFLAGS_CONTAINS_LOOKBEHIND;
extern const MetaFlags METAFLAGS_CONTAINS_LOOKAHEAD;

extern const NodeFlags NODE_FLAGS_ZERO;
extern const NodeFlags NODE_FLAGS_IS_CHECKED;
extern const NodeFlags NODE_FLAGS_IS_EMPTY;

// ---------------------------------------------------------------------------
// NodeId vocabulary helpers (used by parser, engine).
// ---------------------------------------------------------------------------

[[nodiscard]] uint32_t nodeid_as_u32(NodeId n);
[[nodiscard]] NodeId   nodeid_from_u32(uint32_t v);
[[nodiscard]] bool     nodeid_eq(NodeId a, NodeId b);
[[nodiscard]] bool     nodeid_is_missing(NodeId self);
[[nodiscard]] NodeId   nodeid_missing_to_eps(NodeId self);

[[nodiscard]] Kind        nodeid_kind(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_is_kind(NodeId self, const RegexBuilder *b, Kind k);
[[nodiscard]] bool        nodeid_is_pred(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_is_star(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_is_concat(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_is_inter(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_is_compl(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_is_union(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_is_lookahead(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_is_lookbehind(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_is_plus(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_is_begin(NodeId self);
[[nodiscard]] bool        nodeid_is_end(NodeId self);
[[nodiscard]] bool        nodeid_is_ts(NodeId self);
[[nodiscard]] bool        nodeid_is_never_nullable(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_is_center_nullable(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_is_begin_nullable(NodeId self, const RegexBuilder *b);
[[nodiscard]] Nullability nodeid_nullability(NodeId self, const RegexBuilder *b);
[[nodiscard]] NodeId      nodeid_left(NodeId self, const RegexBuilder *b);
[[nodiscard]] NodeId      nodeid_right(NodeId self, const RegexBuilder *b);
[[nodiscard]] uint32_t    nodeid_extra(NodeId self, const RegexBuilder *b);
[[nodiscard]] TSetId      nodeid_pred_tset(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_contains_lookbehind(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_contains_lookahead(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_contains_lookaround(NodeId self, const RegexBuilder *b);
[[nodiscard]] bool        nodeid_has_concat_tail(NodeId self, const RegexBuilder *b, NodeId tail);
[[nodiscard]] bool        nodeid_is_pred_star(NodeId self, const RegexBuilder *b, NodeId *out);
[[nodiscard]] bool        nodeid_is_opt_v(NodeId self, const RegexBuilder *b, NodeId *out);
[[nodiscard]] bool        nodeid_is_contains(NodeId self, const RegexBuilder *b, NodeId *out);
[[nodiscard]] bool        nodeid_is_compl_plus_end(NodeId self, const RegexBuilder *b);
[[nodiscard]] MetaFlags   nodeid_flags_contains(NodeId self, const RegexBuilder *b);

// ---------------------------------------------------------------------------
// TRegex (transition-regex) accessors needed by sibling TUs.
// ---------------------------------------------------------------------------

extern const TRegexId TREGEX_ID_MISSING;
extern const TRegexId TREGEX_ID_EPS;
extern const TRegexId TREGEX_ID_BOT;
extern const TRegexId TREGEX_ID_TOP;
extern const TRegexId TREGEX_ID_TOPSTAR;

[[nodiscard]] bool tregex_id_eq(TRegexId a, TRegexId b);

// Followed transition: walk @p der under the path predicate @p set and
// return the leaf NodeId reached.
NodeId regex_builder_transition_term(RegexBuilder *self, TRegexId der, TSetId set);

// Cached symbolic-derivative bookkeeping.
TRegexId regex_builder_cache_der(RegexBuilder *self, NodeId node_id,
                                 TRegexId result, Nullability mask);
bool     regex_builder_try_cached_der(RegexBuilder *self, NodeId node_id,
                                      Nullability mask, TRegexId *out);

// Public form used by the saturation helpers: caller-managed growable
// `n00b_alloc_array`-backed `NodeId` buffer (data, len, cap).
typedef struct VecNodeIdPub { NodeId *data; size_t len; size_t cap; } VecNodeIdPub;
void regex_builder_extract_sat(const RegexBuilder *self, TRegexId term_id, VecNodeIdPub *out);

// ---------------------------------------------------------------------------
// Engine-side helpers exposed through algebra.h for cross-TU use.
// ---------------------------------------------------------------------------

bool nullability_mask_has_center(Nullability mask);
bool nullability_mask_has_end(Nullability mask);

uint32_t nullstate_rel(NullState ns);
bool     nullstate_is_mask_nullable(NullState ns, Nullability mask);

// `n00b_regex_algebra_err_free` is the engine-side typedef bridge; the err
// type is a plain enum (cast to int) so this is a no-op.
void n00b_regex_algebra_err_free(int *e);

// `mk_compl_outer` is the simplifier path used when complementing a freshly
// constructed `union(left.body, right.body)`.
NodeId regex_builder_mk_compl_outer(RegexBuilder *self, NodeId body);
