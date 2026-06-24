// algebra.c — Boolean algebra and symbolic rewriting engine for the n00b
// regex.
//
// Per § 0a-Z: typed translation of upstream Rust resharp `algebra`, with
// resharp-c's xalloc / HASHMAP / VEC macro shims and abort-on-failure
// PANIC/REQUIRE/UNREACHABLE wrappers replaced by their n00b primitives:
//
//   FxHashMap<K, V>          -> n00b_dict_t(K, V) — `skip_obj_hash = true`
//                               for POD keys (NodeKey, Pair*, TRegex), so
//                               n00b_hash_raw(key, ksz) drives content
//                               equality.  Keys are zero-initialised via the
//                               C23 `{}` idiom so padding bytes are stable.
//   Vec<T> (single-owner)    -> raw n00b_alloc_array(T, N) + manual geometric
//                               grow + n00b_free.  n00b_array_t(T) would
//                               carry an unused rwlock pointer for what is
//                               always single-owner builder state indexed by
//                               id; we follow the same pattern as solver.c
//                               and the helper macro from nulls.c.
//   xalloc shim              -> n00b_alloc / n00b_alloc_array / n00b_free.
//                               xrealloc(_into) becomes alloc-new + memcpy
//                               (D13) + n00b_free, identical to the helper
//                               in nulls.c.
//   pthread / atomics        -> not used by algebra.c (clean).
//   PANIC_FMT / PANIC        -> n00b_panic(fmt, ...) (D9).
//   REQUIRE / FFI_REQUIRE_*  -> n00b_require(cond, msg) (D8) with a single-
//                               line message rendered at the call site.
//                               BOUNDS_CHECK_ID translates to the same.
//   UNREACHABLE              -> n00b_unreachable() (D10).
//   StrBuf (pretty-print)    -> n00b_buffer_t (D12) with .no_lock = true.
//   printf / vsnprintf       -> n00b_cformat(...) for integer formatting,
//                               with the resulting n00b_string_t bytes
//                               appended to the buffer (D14 conduit/print
//                               replaces stdio).
//   ckd_mul_sz / ckd_add_sz  -> <stdckdint.h> directly per § 15(C).
//
// Algorithmic shape and control flow are unchanged from upstream Rust /
// resharp-c, including the canonical hash-cons interning, the symbolic
// derivative cache, and the union/inter rewrite cascades.

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdckdint.h>
#include <string.h> // memcpy / memset / memmove (D13)

#include "n00b.h"
#include "adt/variant.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/string.h"
#include "adt/dict.h"
#include "text/strings/format.h"
#include "util/assert.h"
#include "util/panic.h"

#include "internal/regex/algebra.h"
#include "internal/regex/ids.h"
#include "internal/regex/solver.h"
#include "internal/regex/nulls.h"

// ----------------------------------------------------------------------------
// unicode_classes_utf8_char comes from the unicode_classes module.
// ----------------------------------------------------------------------------

extern NodeId unicode_classes_utf8_char(RegexBuilder *self);

// ============================================================================
// Capacity / size helpers — checked-arithmetic wrappers around <stdckdint.h>
// (§ 15(C) permits the language header directly).  On overflow we route to
// n00b_panic so the abort path is loud and consistent.
// ============================================================================

[[noreturn]] static inline void
algebra_capacity_overflow(void)
{
    n00b_panic("algebra.c: capacity overflow");
}

static inline size_t
safe_mul_sz(size_t a, size_t b)
{
    size_t r;
    if (ckd_mul(&r, a, b)) {
        algebra_capacity_overflow();
    }
    return r;
}

static inline size_t
safe_add_sz(size_t a, size_t b)
{
    size_t r;
    if (ckd_add(&r, a, b)) {
        algebra_capacity_overflow();
    }
    return r;
}

static inline size_t
safe_add3_sz(size_t a, size_t b, size_t c)
{
    return safe_add_sz(safe_add_sz(a, b), c);
}

// Geometric grow for a single-owner `T data[]` with `len`/`cap` book-keeping.
// Allocates a new buffer at the requested capacity, copies @p old_len
// elements, frees the old buffer.  Mirrors `solver.c`'s grow pattern.
// The buffers grown here hold POD scalars (MetadataId, NodeId, NodeKey,
// TRegex, TRegexId — all uint32_t-shaped); marking them `no_scan` keeps
// the conservative GC scanner from mis-identifying adjacent uint32_t
// pairs as 8-byte heap pointers and rewriting them.
//
// @p alloc routes the new buffer through a caller-supplied allocator
// (typically the per-regex pool from gc-bits.md Step 5); pass nullptr
// to use the runtime default.
#define grow_buf(T, alloc, p_data, p_cap, old_len, new_cap)         \
    do {                                                            \
        size_t _gb_nc = (new_cap);                                  \
        T *_gb_new = n00b_alloc_array_with_opts(T, _gb_nc,          \
            &(n00b_alloc_opts_t){                                   \
                .allocator = (alloc),                               \
                .scan_kind = N00B_GC_SCAN_KIND_NONE,                \
            });                                                     \
        if ((old_len) > 0 && *(p_data) != nullptr) {                \
            memcpy(_gb_new, *(p_data),                              \
                   safe_mul_sz((old_len), sizeof(T)));              \
        }                                                           \
        if (*(p_data) != nullptr) {                                 \
            n00b_free(*(p_data));                                   \
        }                                                           \
        *(p_data) = _gb_new;                                        \
        *(p_cap)  = _gb_nc;                                         \
    } while (0)

// ============================================================================
// n00b_regex_algebra_err_str
// ============================================================================

const char *
n00b_regex_algebra_err_str(int kind)
{
    switch ((n00b_regex_algebra_err_t)kind) {
    case N00B_REGEX_ALGEBRA_ERR_ANCHOR_LIMIT:          return "anchor limit exceeded";
    case N00B_REGEX_ALGEBRA_ERR_STATE_SPACE_EXPLOSION: return "too many states, likely infinite state space";
    case N00B_REGEX_ALGEBRA_ERR_UNSUPPORTED_PATTERN:   return "unsupported lookaround pattern";
    default:                                           return "ok";
    }
}

// ============================================================================
// Sentinel id constants (NodeIds defined at the bottom of the file).
// ============================================================================

constexpr MetadataId METADATA_ID_MISSING = (MetadataId){ 0 };

// TRegex sentinel ids (defined as `extern const` for sibling TUs).
const TRegexId TREGEX_ID_MISSING = (TRegexId){ 0 };
const TRegexId TREGEX_ID_BOT     = (TRegexId){ 1 };
const TRegexId TREGEX_ID_EPS     = (TRegexId){ 2 };
const TRegexId TREGEX_ID_TOP     = (TRegexId){ 3 };
const TRegexId TREGEX_ID_TOPSTAR = (TRegexId){ 4 };

bool
tregex_id_eq(TRegexId a, TRegexId b)
{
    return a.v == b.v;
}

uint32_t
nodeid_as_u32(NodeId n)
{
    return n.v;
}

NodeId
nodeid_from_u32(uint32_t v)
{
    return (NodeId){ v };
}

bool
nodeid_eq(NodeId a, NodeId b)
{
    return a.v == b.v;
}

// ============================================================================
// MetaFlags / NodeFlags constants and helpers.
// ============================================================================

constexpr uint8_t METAFLAGS_NULL_MASK_BITS_V = 0b111;

const MetaFlags METAFLAGS_ZERO                = (MetaFlags){ 0 };
const MetaFlags METAFLAGS_INFINITE_LENGTH     = (MetaFlags){ 1u << 3 };
const MetaFlags METAFLAGS_CONTAINS_INTER      = (MetaFlags){ 1u << 4 };
const MetaFlags METAFLAGS_CONTAINS_ANCHORS    = (MetaFlags){ 1u << 5 };
const MetaFlags METAFLAGS_CONTAINS_LOOKBEHIND = (MetaFlags){ 1u << 6 };
const MetaFlags METAFLAGS_CONTAINS_LOOKAHEAD  = (MetaFlags){ 1u << 7 };

const NodeFlags NODE_FLAGS_ZERO       = (NodeFlags){ 0 };
const NodeFlags NODE_FLAGS_IS_CHECKED = (NodeFlags){ 1 };
const NodeFlags NODE_FLAGS_IS_EMPTY   = (NodeFlags){ 1u << 1 };

Nullability
metaflags_nullability(MetaFlags self)
{
    return (Nullability){ (uint8_t)(self.v & METAFLAGS_NULL_MASK_BITS_V) };
}

MetaFlags
metaflags_with_nullability(Nullability n, MetaFlags flags)
{
    return (MetaFlags){
        (uint8_t)((flags.v & ~METAFLAGS_NULL_MASK_BITS_V) | n.v)
    };
}

bool
metaflags_has(MetaFlags self, MetaFlags flag)
{
    return (self.v & flag.v) != 0;
}

MetaFlags
metaflags_and(MetaFlags self, MetaFlags other)
{
    return (MetaFlags){ (uint8_t)(self.v & other.v) };
}

MetaFlags
metaflags_or(MetaFlags self, MetaFlags other)
{
    return (MetaFlags){ (uint8_t)(self.v | other.v) };
}

bool
metaflags_contains_inter(MetaFlags self)
{
    return metaflags_has(self, METAFLAGS_CONTAINS_INTER);
}

MetaFlags
metaflags_all_contains_flags(MetaFlags self)
{
    MetaFlags mask = metaflags_or(
        metaflags_or(METAFLAGS_CONTAINS_ANCHORS, METAFLAGS_CONTAINS_INTER),
        metaflags_or(METAFLAGS_CONTAINS_LOOKBEHIND, METAFLAGS_CONTAINS_LOOKAHEAD));
    return metaflags_and(self, mask);
}

bool
node_flags_is_checked(NodeFlags f)
{
    return f.v >= NODE_FLAGS_IS_CHECKED.v;
}

bool
node_flags_is_empty(NodeFlags f)
{
    return (f.v & NODE_FLAGS_IS_EMPTY.v) == NODE_FLAGS_IS_EMPTY.v;
}

bool
nodeflags_is_checked(NodeFlags f)
{
    return node_flags_is_checked(f);
}

bool
nodeflags_is_empty(NodeFlags f)
{
    return node_flags_is_empty(f);
}

// ----------------------------------------------------------------------------
// helpers::incr_rel — saturate at UINT32_MAX.
// ----------------------------------------------------------------------------

uint32_t
helpers_incr_rel(uint32_t n1)
{
    uint32_t res = n1 + 1;
    if (res < n1) return UINT32_MAX;
    return res;
}

// ============================================================================
// Metadata + MetadataIndex — file-private content-keyed dedup.
// ============================================================================

typedef struct Metadata {
    MetaFlags flags;
    NullsId   nulls;
} Metadata;

static_assert(sizeof(Metadata) == 8,
              "Metadata must be 8 bytes (no padding) for skip_obj_hash dict");

static bool
metadata_eq(const Metadata *a, const Metadata *b)
{
    return a->flags.v == b->flags.v && a->nulls.v == b->nulls.v;
}

// Typed dict for `Metadata -> MetadataId`.  Metadata is 8 bytes of POD with
// no padding (asserted above), so skip_obj_hash hashes the raw bits.
typedef n00b_dict_t(Metadata, MetadataId) MetadataIndexMap;

// Raw growable Vec<Metadata>.
typedef struct MetadataVec {
    Metadata *data;
    size_t    len;
    size_t    cap;
} MetadataVec;

static void
metadata_vec_push(MetadataVec *v, Metadata m, n00b_allocator_t *allocator)
{
    if (v->len == v->cap) {
        size_t nc = v->cap ? safe_mul_sz(v->cap, 2) : 8;
        grow_buf(Metadata, allocator, &v->data, &v->cap, v->len, nc);
    }
    v->data[v->len++] = m;
}

typedef struct MetadataBuilder {
    uint32_t          num_created;
    Solver           *solver;
    NullsBuilder      nb;
    MetadataIndexMap *index;
    MetadataVec       array;
    /* Per-builder allocator (forwarded from RegexBuilder.allocator).  See
     * gc-bits.md Step 5 — when non-null, every allocation made by the
     * metadata builder routes through this allocator instead of the
     * runtime default. */
    n00b_allocator_t *allocator;
} MetadataBuilder;

static MetadataBuilder
metadata_builder_new(n00b_allocator_t *allocator)
{
    MetadataBuilder mb = {};
    mb.allocator   = allocator;
    mb.num_created = 0;
    mb.solver      = solver_new(allocator);
    mb.nb          = nulls_builder_new(allocator);
    mb.index       = n00b_alloc_with_opts(
        MetadataIndexMap, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(mb.index, .skip_obj_hash = true, .allocator = allocator,
                   .scan_kind = N00B_GC_SCAN_KIND_NONE);
    mb.array = (MetadataVec){};
    Metadata zero = (Metadata){ METAFLAGS_ZERO, NULLS_ID_EMPTY };
    metadata_vec_push(&mb.array, zero, allocator);
    return mb;
}

static MetadataId
metadata_builder_init(MetadataBuilder *mb, Metadata inst)
{
    mb->num_created += 1;
    MetadataId new_id = (MetadataId){ mb->num_created };
    n00b_dict_put(mb->index, inst, new_id);
    metadata_vec_push(&mb->array, inst, mb->allocator);
    return new_id;
}

static MetadataId
metadata_builder_get_meta_id(MetadataBuilder *mb, Metadata inst)
{
    bool       found;
    MetadataId existing = n00b_dict_get(mb->index, inst, &found);
    if (found) return existing;
    return metadata_builder_init(mb, inst);
}

static const Metadata *
metadata_builder_get_meta_ref(MetadataBuilder *mb, MetadataId id)
{
    n00b_require((size_t)id.v < mb->array.len, "MetadataId out of bounds");
    return &mb->array.data[id.v];
}

static MetaFlags
metadata_builder_get_contains([[maybe_unused]] const MetadataBuilder *mb,
                              MetaFlags setflags)
{
    return metaflags_all_contains_flags(setflags);
}

static MetaFlags
metadata_builder_flags_star(const MetadataBuilder *mb,
                            MetadataId body, NodeId body_id)
{
    MetaFlags left     = mb->array.data[body.v].flags;
    MetaFlags contains = metadata_builder_get_contains(mb, left);
    MetaFlags inf      = nodeid_eq(body_id, NODE_ID_BOT)
                             ? METAFLAGS_ZERO
                             : METAFLAGS_INFINITE_LENGTH;
    return metaflags_with_nullability(NULLABILITY_ALWAYS,
                                      metaflags_or(contains, inf));
}

static MetaFlags
metadata_builder_flags_compl(const MetadataBuilder *mb, MetadataId left_id)
{
    MetaFlags   left     = mb->array.data[left_id.v].flags;
    Nullability null     = nullability_and(nullability_not(metaflags_nullability(left)),
                                           NULLABILITY_ALWAYS);
    MetaFlags   contains = metadata_builder_get_contains(mb, left);
    return metaflags_with_nullability(null,
                                      metaflags_or(contains,
                                                   METAFLAGS_INFINITE_LENGTH));
}

static MetaFlags
metadata_builder_flags_concat(const MetadataBuilder *mb,
                              MetadataId left_id, MetadataId right_id)
{
    MetaFlags   left     = mb->array.data[left_id.v].flags;
    MetaFlags   right    = mb->array.data[right_id.v].flags;
    Nullability null     = nullability_and(metaflags_nullability(left),
                                           metaflags_nullability(right));
    MetaFlags   contains = metadata_builder_get_contains(mb, metaflags_or(left, right));
    MetaFlags   len      = metaflags_and(metaflags_or(left, right),
                                         METAFLAGS_INFINITE_LENGTH);
    return metaflags_with_nullability(null, metaflags_or(contains, len));
}

static MetaFlags
metadata_builder_flags_inter(const MetadataBuilder *mb,
                             MetadataId left_id, MetadataId right_id)
{
    MetaFlags   left     = mb->array.data[left_id.v].flags;
    MetaFlags   right    = mb->array.data[right_id.v].flags;
    Nullability null     = nullability_and(metaflags_nullability(left),
                                           metaflags_nullability(right));
    MetaFlags   contains = metaflags_or(
        metadata_builder_get_contains(mb, metaflags_or(left, right)),
        METAFLAGS_CONTAINS_INTER);
    MetaFlags   len      = metaflags_and(metaflags_and(left, right),
                                         METAFLAGS_INFINITE_LENGTH);
    return metaflags_with_nullability(null, metaflags_or(contains, len));
}

static MetaFlags
metadata_builder_flags_union(const MetadataBuilder *mb,
                             MetadataId left_id, MetadataId right_id)
{
    MetaFlags   left     = mb->array.data[left_id.v].flags;
    MetaFlags   right    = mb->array.data[right_id.v].flags;
    Nullability null     = nullability_or(metaflags_nullability(left),
                                          metaflags_nullability(right));
    MetaFlags   contains = metadata_builder_get_contains(mb, metaflags_or(left, right));
    MetaFlags   len      = metaflags_and(metaflags_or(left, right),
                                         METAFLAGS_INFINITE_LENGTH);
    return metaflags_with_nullability(null, metaflags_or(contains, len));
}

// ============================================================================
// NodeKey — hash-cons key (Kind + 2 NodeIds + extra).
// `NodeKey` is 16 bytes total on every supported target: 1 (Kind) + 3 pad +
// 4 (NodeId) + 4 (NodeId) + 4 (uint32_t).  Padding bytes are deterministic
// because every NodeKey is constructed via a designated-initialiser list
// (or the `{}` zero-init idiom) which zero-fills holes per C23.
// ============================================================================

static_assert(sizeof(NodeKey) == 16, "NodeKey must be 16 bytes for skip_obj_hash dict");

bool node_key_eq(const NodeKey *a, const NodeKey *b);

bool
node_key_eq(const NodeKey *a, const NodeKey *b)
{
    return a->kind == b->kind && a->left.v == b->left.v
        && a->right.v == b->right.v && a->extra == b->extra;
}

// Typed dict: `n00b_dict_t(NodeKey, NodeId)`.  16-byte key, no padding holes,
// content-equality via skip_obj_hash + n00b_hash_raw.
typedef n00b_dict_t(NodeKey, NodeId) NodeKeyMap;

// ============================================================================
// TRegex<TSet> (TSet = TSetId).
// ============================================================================

// Hoisted variant arms for TRegex_TSetId (formerly the anonymous `leaf` /
// `ite` structs inside the bare union).  Distinct named types so the
// n00b_variant_t selector can discriminate them by typehash.
typedef struct TRegex_leaf_t {
    NodeId leaf;
} TRegex_leaf_t;

typedef struct TRegex_ite_t {
    TSetId   set;
    TRegexId then_id;
    TRegexId else_id;
} TRegex_ite_t;

typedef n00b_variant_t(TRegex_leaf_t, TRegex_ite_t) TRegex_TSetId;

static bool
tregex_eq(const TRegex_TSetId *a, const TRegex_TSetId *b)
{
    if (a->selector != b->selector) return false;
    if (n00b_variant_is_type(*a, TRegex_leaf_t)) {
        return n00b_variant_get(*a, TRegex_leaf_t).leaf.v
            == n00b_variant_get(*b, TRegex_leaf_t).leaf.v;
    }
    TRegex_ite_t _a = n00b_variant_get(*a, TRegex_ite_t);
    TRegex_ite_t _b = n00b_variant_get(*b, TRegex_ite_t);
    return _a.set.v == _b.set.v
        && _a.then_id.v == _b.then_id.v
        && _a.else_id.v == _b.else_id.v;
}

// TRegex hash — content-aware, used by the typed dict's custom `hash` fn.
// The dict invokes `fn(*(void **)key)`, so the void * passed in is a
// `TRegex_TSetId *`.
static n00b_uint128_t
tregex_ptr_hash(void *opaque)
{
    const TRegex_TSetId *t = (const TRegex_TSetId *)opaque;
    // Pack the discriminant + payload into a stable 16-byte buffer; padding
    // bits inside the union may be undefined for the inactive variant.
    struct {
        uint32_t tag;
        uint32_t a;
        uint32_t b;
        uint32_t c;
    } packed = {};
    packed.tag = (uint32_t)t->selector;
    if (n00b_variant_is_type(*t, TRegex_leaf_t)) {
        packed.a = n00b_variant_get(*t, TRegex_leaf_t).leaf.v;
    }
    else {
        TRegex_ite_t _i = n00b_variant_get(*t, TRegex_ite_t);
        packed.a = _i.set.v;
        packed.b = _i.then_id.v;
        packed.c = _i.else_id.v;
    }
    return n00b_hash_raw(&packed, sizeof(packed));
}

// Typed dict for `n00b_dict_t(TRegex_TSetId *, TRegexId)`.  Pointer keys with
// content-aware hash via tregex_ptr_hash; equality is by `tregex_eq` —
// **but** n00b_dict_t equality is purely 128-bit hash equality (see solver.c
// / nulls.c rationale); a 128-bit hash over the packed key has effectively
// zero collision rate and matches the resharp-c dedup path.
typedef n00b_dict_t(TRegex_TSetId *, TRegexId) TRegexMap;

// ============================================================================
// PairTR / PairTSetTR — 8-byte POD keys, no padding holes.
// ============================================================================

typedef struct PairTR { TRegexId a; TRegexId b; } PairTR;
typedef struct PairTSetTR { TSetId s; TRegexId t; } PairTSetTR;

static_assert(sizeof(PairTR) == 8, "PairTR must be 8 bytes");
static_assert(sizeof(PairTSetTR) == 8, "PairTSetTR must be 8 bytes");

typedef n00b_dict_t(PairTR, TRegexId)     PairTRMap;
typedef n00b_dict_t(PairTSetTR, TRegexId) PairTSetTRMap;

// ============================================================================
// NodeFlagsMap — (NodeId -> NodeFlags), keyed by 4-byte NodeId.
// ============================================================================

typedef n00b_dict_t(NodeId, NodeFlags) NodeFlagsMap;

// ============================================================================
// Raw growable Vec<T> for fields embedded directly in `RegexBuilder`.
// Each type is a plain struct; growth uses `grow_buf`.  No locking — the
// builder is single-owner.
// ============================================================================

typedef struct VecNodeId      { NodeId        *data; size_t len; size_t cap; } VecNodeId;
typedef struct VecMetadataId  { MetadataId    *data; size_t len; size_t cap; } VecMetadataId;
typedef struct VecNodeKey     { NodeKey       *data; size_t len; size_t cap; } VecNodeKey;
typedef struct VecTRegex      { TRegex_TSetId *data; size_t len; size_t cap; } VecTRegex;
typedef struct VecTRegexId    { TRegexId      *data; size_t len; size_t cap; } VecTRegexId;

#define DEFINE_VEC_PUSH(NAME, T)                                       \
    static void NAME##_push(NAME *v, T x, n00b_allocator_t *allocator) \
    {                                                                  \
        if (v->len == v->cap) {                                        \
            size_t nc = v->cap ? safe_mul_sz(v->cap, 2) : 8;           \
            grow_buf(T, allocator, &v->data, &v->cap, v->len, nc);     \
        }                                                              \
        v->data[v->len++] = x;                                         \
    }

DEFINE_VEC_PUSH(VecNodeId,     NodeId)
DEFINE_VEC_PUSH(VecMetadataId, MetadataId)
DEFINE_VEC_PUSH(VecNodeKey,    NodeKey)
DEFINE_VEC_PUSH(VecTRegex,     TRegex_TSetId)
DEFINE_VEC_PUSH(VecTRegexId,   TRegexId)

// Per-regex_builder_mk_unions slow-path: NodeId head -> growable Vec<NodeId>
// tails.  `GroupTails` is stored *by value* in a typed dict; the inner
// `data` pointer lives in the n00b heap and is freed manually in the slow
// path's teardown.
typedef struct GroupTails {
    NodeId *data;
    size_t  len;
    size_t  cap;
} GroupTails;

static void
group_tails_push(GroupTails *gt, NodeId v, n00b_allocator_t *allocator)
{
    if (gt->len == gt->cap) {
        size_t nc = gt->cap ? safe_mul_sz(gt->cap, 2) : 4;
        grow_buf(NodeId, allocator, &gt->data, &gt->cap, gt->len, nc);
    }
    gt->data[gt->len++] = v;
}

typedef n00b_dict_t(NodeId, GroupTails) NodeIdGroupMap;
typedef n00b_dict_t(NodeId, bool)       NodeIdHashSet;
typedef n00b_dict_t(NodeId, NodeId)     NodeIdHashMap;
typedef n00b_dict_t(NodeId, uint32_t)   NodeIdU32Map;

// ============================================================================
// Builder flags.
// ============================================================================

typedef struct { uint8_t v; } BuilderFlags;
constexpr BuilderFlags BUILDER_FLAGS_ZERO    = (BuilderFlags){ 0 };
constexpr BuilderFlags BUILDER_FLAGS_SUBSUME = (BuilderFlags){ 1 };

// ============================================================================
// RegexBuilder
// ============================================================================

struct RegexBuilder {
    MetadataBuilder    mb;
    VecNodeId          temp_vec;
    uint32_t           num_created;
    NodeKeyMap        *index;
    VecNodeKey         array;
    VecMetadataId      metadata;
    VecNodeId          reversed;
    NodeFlagsMap      *cache_empty;
    TRegexMap         *tr_cache;
    VecTRegex          tr_array;
    VecTRegexId        tr_der_center;
    VecTRegexId        tr_der_begin;
    BuilderFlags       flags;
    uint32_t           lookahead_context_max;
    PairTRMap         *mk_binary_memo;
    PairTSetTRMap     *clean_cache;
    /* Sticky state-space-explosion latch.  Tripped by
     * `regex_builder_tr_init` when `tr_array.len` exceeds the per-builder
     * cap.  Checked by `regex_builder_der`, which surfaces
     * `N00B_REGEX_ALGEBRA_ERR_STATE_SPACE_EXPLOSION` to its caller.  The
     * per-mk_binary-call memo growth that used to compound here is now
     * bounded by in-place dict clear (see `regex_builder_mk_binary`). */
    bool               state_space_err;
    /**
     * Per-builder allocator.  When non-null, every allocation made by
     * the builder (and its embedded MetadataBuilder / Solver / NullsBuilder
     * subsystems) targets this allocator instead of the runtime default.
     * Used to route a compile through a per-regex pool so the GC never
     * fires during compile — see gc-bits.md Step 5.
     */
    n00b_allocator_t  *allocator;
};

// ----------------------------------------------------------------------------
// NodeKey-map helpers (thin wrappers around the typed dict).
// ----------------------------------------------------------------------------

static bool
node_key_map_get(NodeKeyMap *m, NodeKey k, NodeId *out)
{
    bool   found;
    NodeId got = n00b_dict_get(m, k, &found);
    if (found) *out = got;
    return found;
}

static void
node_key_map_insert(NodeKeyMap *m, NodeKey k, NodeId v)
{
    n00b_dict_put(m, k, v);
}

// NodeFlags-map helpers.
static bool
node_flags_map_get(NodeFlagsMap *m, NodeId k, NodeFlags *out)
{
    bool      found;
    NodeFlags got = n00b_dict_get(m, k, &found);
    if (found) *out = got;
    return found;
}

static void
node_flags_map_insert(NodeFlagsMap *m, NodeId k, NodeFlags v)
{
    n00b_dict_put(m, k, v);
}

// TRegex-map helpers — the typed dict stores `TRegex_TSetId *` (pointer)
// keys; allocation of a heap copy is the caller's responsibility.
static bool
tregex_map_get(TRegexMap *m, const TRegex_TSetId *k, TRegexId *out)
{
    bool             found;
    TRegex_TSetId   *kp  = (TRegex_TSetId *)k;
    TRegexId         got = n00b_dict_get(m, kp, &found);
    if (found) *out = got;
    return found;
}

static void
tregex_map_insert(TRegexMap *m, TRegex_TSetId k, TRegexId v,
                  n00b_allocator_t *allocator)
{
    // n00b_dict_put copies the pointer-sized key bits; the dict's hash is
    // content-aware (tregex_ptr_hash) and reads through the pointer.  We
    // need a stable heap copy of the value before insertion.  The copy
    // MUST come from the same allocator as the dict's internal store
    // (the per-regex pool) so a GC can't move it and leave a stale key
    // behind in the (hidden) pool dict.
    TRegex_TSetId *kp = n00b_alloc_with_opts(
        TRegex_TSetId, &(n00b_alloc_opts_t){.allocator = allocator});
    *kp = k;
    n00b_dict_put(m, kp, v);
}

// PairTR-map helpers.
static bool
pair_tr_map_get(PairTRMap *m, PairTR k, TRegexId *out)
{
    bool     found;
    TRegexId got = n00b_dict_get(m, k, &found);
    if (found) *out = got;
    return found;
}

static void
pair_tr_map_insert(PairTRMap *m, PairTR k, TRegexId v)
{
    n00b_dict_put(m, k, v);
}

// PairTSetTR-map helpers.
static bool
pair_tset_tr_map_get(PairTSetTRMap *m, PairTSetTR k, TRegexId *out)
{
    bool     found;
    TRegexId got = n00b_dict_get(m, k, &found);
    if (found) *out = got;
    return found;
}

static void
pair_tset_tr_map_insert(PairTSetTRMap *m, PairTSetTR k, TRegexId v)
{
    n00b_dict_put(m, k, v);
}

// NodeIdHashSet helpers — `n00b_dict_t(NodeId, bool)` with unit-true value.
static bool
NodeIdHashSet_insert(NodeIdHashSet *s, NodeId k)
{
    // Returns true on newly-inserted, false on already-present.
    if (n00b_dict_contains(s, k)) return false;
    bool t = true;
    n00b_dict_put(s, k, t);
    return true;
}

static bool
NodeIdHashSet_contains(NodeIdHashSet *s, NodeId k)
{
    return n00b_dict_contains(s, k);
}

static size_t
NodeIdHashSet_len(NodeIdHashSet *s)
{
    return (size_t)n00b_dict_internal_len((_n00b_dict_internal_t *)s);
}

// NodeIdHashSet allocator (lazy alloc).
static NodeIdHashSet *
NodeIdHashSet_new(n00b_allocator_t *allocator)
{
    NodeIdHashSet *s = n00b_alloc_with_opts(
        NodeIdHashSet, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(s, .skip_obj_hash = true, .allocator = allocator,
                   .scan_kind = N00B_GC_SCAN_KIND_NONE);
    return s;
}

// NodeIdHashMap helpers.
static NodeIdHashMap *
NodeIdHashMap_new(n00b_allocator_t *allocator)
{
    NodeIdHashMap *m = n00b_alloc_with_opts(
        NodeIdHashMap, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(m, .skip_obj_hash = true, .allocator = allocator,
                   .scan_kind = N00B_GC_SCAN_KIND_NONE);
    return m;
}

static bool
NodeIdHashMap_get(NodeIdHashMap *m, NodeId k, NodeId *out)
{
    bool   found;
    NodeId got = n00b_dict_get(m, k, &found);
    if (found) *out = got;
    return found;
}

static void
NodeIdHashMap_insert(NodeIdHashMap *m, NodeId k, NodeId v)
{
    n00b_dict_put(m, k, v);
}

// NodeIdU32Map helpers.
static NodeIdU32Map *
NodeIdU32Map_new(n00b_allocator_t *allocator)
{
    NodeIdU32Map *m = n00b_alloc_with_opts(
        NodeIdU32Map, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(m, .skip_obj_hash = true, .allocator = allocator,
                   .scan_kind = N00B_GC_SCAN_KIND_NONE);
    return m;
}

static bool
NodeIdU32Map_get(NodeIdU32Map *m, NodeId k, uint32_t *out)
{
    bool     found;
    uint32_t got = n00b_dict_get(m, k, &found);
    if (found) *out = got;
    return found;
}

static void
NodeIdU32Map_insert(NodeIdU32Map *m, NodeId k, uint32_t v)
{
    n00b_dict_put(m, k, v);
}

// NodeIdGroupMap helpers.
static NodeIdGroupMap *
NodeIdGroupMap_new(n00b_allocator_t *allocator)
{
    NodeIdGroupMap *m = n00b_alloc_with_opts(
        NodeIdGroupMap, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(m, .skip_obj_hash = true, .allocator = allocator);
    return m;
}

static bool
NodeIdGroupMap_get(NodeIdGroupMap *m, NodeId k, GroupTails *out)
{
    bool       found;
    GroupTails got = n00b_dict_get(m, k, &found);
    if (found) *out = got;
    return found;
}

static void
NodeIdGroupMap_insert(NodeIdGroupMap *m, NodeId k, GroupTails v)
{
    n00b_dict_put(m, k, v);
}

// ============================================================================
// Forward declarations of cross-cutting helpers.
// ============================================================================

extern NodeId      regex_builder_mk_compl(RegexBuilder *self, NodeId body);
extern NodeId      regex_builder_mk_inter(RegexBuilder *self, NodeId l, NodeId r);
extern NodeId      regex_builder_mk_union(RegexBuilder *self, NodeId l, NodeId r);
extern NodeId      regex_builder_mk_concat(RegexBuilder *self, NodeId head, NodeId tail);
extern NodeId      regex_builder_mk_lookahead_internal(RegexBuilder *self, NodeId body, NodeId tail, uint32_t rel);
static NodeId      regex_builder_mk_unset(RegexBuilder *self, Kind kind);
static TRegexId    regex_builder_mk_leaf(RegexBuilder *self, NodeId node_id);
static const TRegex_TSetId *regex_builder_get_tregex(const RegexBuilder *self, TRegexId inst);
static NodeId      regex_builder_init(RegexBuilder *self, NodeKey inst);
static NodeId      regex_builder_init_as(RegexBuilder *self, NodeKey key, NodeId subsumed);
static NodeId      regex_builder_get_node_id(RegexBuilder *self, NodeKey inst);
static NodeId      regex_builder_post_init_simplify(RegexBuilder *self, NodeId node_id);
static bool        regex_builder_subsumes(RegexBuilder *self, NodeId a, NodeId b, bool *out_known);
static bool        regex_builder_union_branches_subset(RegexBuilder *self, NodeId lhs, NodeId rhs);
static bool        regex_builder_nullable_subsumes(RegexBuilder *self, NodeId node, NodeId target);

// NodeId vocabulary forward decls (full bodies later).
NodeId regex_builder_get_left(const RegexBuilder *self, NodeId node_id);
NodeId regex_builder_get_right(const RegexBuilder *self, NodeId node_id);
uint32_t regex_builder_get_extra(const RegexBuilder *self, NodeId node_id);
Kind regex_builder_get_kind(const RegexBuilder *self, NodeId node_id);
MetaFlags regex_builder_get_meta_flags(const RegexBuilder *self, NodeId node_id);
MetaFlags regex_builder_get_flags_contains(const RegexBuilder *self, NodeId node_id);
Nullability regex_builder_get_only_nullability(const RegexBuilder *self, NodeId node_id);
NullsId regex_builder_get_nulls_id(const RegexBuilder *self, NodeId node_id);
NullsId regex_builder_get_nulls_id_w_mask(RegexBuilder *self, NodeId node_id, Nullability mask);
MetadataId regex_builder_get_node_meta_id(RegexBuilder *self, NodeId n);

// ============================================================================
// NodeId vocabulary helpers (Rust impl NodeId).
// ============================================================================

bool
nodeid_is_missing(NodeId self)
{
    return nodeid_eq(self, NODE_ID_MISSING);
}

MetaFlags
nodeid_flags_contains(NodeId self, const RegexBuilder *b)
{
    return regex_builder_get_flags_contains(b, self);
}

NodeId
nodeid_missing_to_eps(NodeId self)
{
    return nodeid_eq(self, NODE_ID_MISSING) ? NODE_ID_EPS : self;
}

Kind
nodeid_kind(NodeId self, const RegexBuilder *b)
{
    return regex_builder_get_kind(b, self);
}

bool
nodeid_is_kind(NodeId self, const RegexBuilder *b, Kind k)
{
    return regex_builder_get_kind(b, self) == k;
}

bool
nodeid_is_never_nullable(NodeId self, const RegexBuilder *b)
{
    return nullability_eq(regex_builder_nullability(b, self), NULLABILITY_NEVER);
}

Nullability
nodeid_nullability(NodeId self, const RegexBuilder *b)
{
    return regex_builder_nullability(b, self);
}

bool
nodeid_is_center_nullable(NodeId self, const RegexBuilder *b)
{
    return !nullability_eq(nullability_and(regex_builder_nullability(b, self),
                                           NULLABILITY_CENTER),
                           NULLABILITY_NEVER);
}

bool
nodeid_is_begin_nullable(NodeId self, const RegexBuilder *b)
{
    return nullability_has(regex_builder_nullability(b, self), NULLABILITY_BEGIN);
}

NodeId
nodeid_left(NodeId self, const RegexBuilder *b)
{
    return regex_builder_get_left(b, self);
}

NodeId
nodeid_right(NodeId self, const RegexBuilder *b)
{
    return regex_builder_get_right(b, self);
}

uint32_t
nodeid_extra(NodeId self, const RegexBuilder *b)
{
    return regex_builder_get_extra(b, self);
}

bool
nodeid_is_pred(NodeId self, const RegexBuilder *b)
{
    return regex_builder_get_kind(b, self) == KIND_PRED;
}

TSetId
nodeid_pred_tset(NodeId self, const RegexBuilder *b)
{
    return (TSetId){ regex_builder_get_extra(b, self) };
}

bool
nodeid_is_star(NodeId self, const RegexBuilder *b)
{
    if (nodeid_eq(NODE_ID_EPS, self)) return false;
    return regex_builder_get_kind(b, self) == KIND_STAR;
}

bool
nodeid_contains_lookbehind(NodeId self, const RegexBuilder *b)
{
    return metaflags_has(regex_builder_get_meta_flags(b, self),
                         METAFLAGS_CONTAINS_LOOKBEHIND);
}

bool
nodeid_contains_lookahead(NodeId self, const RegexBuilder *b)
{
    return metaflags_has(regex_builder_get_meta_flags(b, self),
                         METAFLAGS_CONTAINS_LOOKAHEAD);
}

bool
nodeid_contains_lookaround(NodeId self, const RegexBuilder *b)
{
    MetaFlags flags = regex_builder_get_meta_flags(b, self);
    return metaflags_has(flags, metaflags_or(METAFLAGS_CONTAINS_LOOKBEHIND,
                                             METAFLAGS_CONTAINS_LOOKAHEAD));
}

bool
nodeid_is_inter(NodeId self, const RegexBuilder *b)
{
    return regex_builder_get_kind(b, self) == KIND_INTER;
}

bool
nodeid_is_compl(NodeId self, const RegexBuilder *b)
{
    return regex_builder_get_kind(b, self) == KIND_COMPL;
}

bool
nodeid_is_concat(NodeId self, const RegexBuilder *b)
{
    return regex_builder_get_kind(b, self) == KIND_CONCAT;
}

bool
nodeid_is_plus(NodeId self, const RegexBuilder *b)
{
    if (nodeid_is_concat(self, b)) {
        NodeId r = regex_builder_get_right(b, self);
        return nodeid_is_star(r, b)
            && nodeid_eq(regex_builder_get_left(b, r),
                         regex_builder_get_left(b, self));
    }
    return false;
}

bool
nodeid_is_begin(NodeId self)
{
    return nodeid_eq(self, NODE_ID_BEGIN);
}

bool
nodeid_is_end(NodeId self)
{
    return nodeid_eq(self, NODE_ID_END);
}

bool
nodeid_is_union(NodeId self, const RegexBuilder *b)
{
    return regex_builder_get_kind(b, self) == KIND_UNION;
}

bool
nodeid_is_lookahead(NodeId self, const RegexBuilder *b)
{
    return regex_builder_get_kind(b, self) == KIND_LOOKAHEAD;
}

bool
nodeid_is_lookbehind(NodeId self, const RegexBuilder *b)
{
    return regex_builder_get_kind(b, self) == KIND_LOOKBEHIND;
}

bool
nodeid_is_opt_v(NodeId self, const RegexBuilder *b, NodeId *out)
{
    if (regex_builder_get_kind(b, self) == KIND_UNION
        && nodeid_eq(regex_builder_get_left(b, self), NODE_ID_EPS)) {
        *out = regex_builder_get_right(b, self);
        return true;
    }
    return false;
}

bool
nodeid_is_compl_plus_end(NodeId self, const RegexBuilder *b)
{
    if (nodeid_is_concat(self, b)) {
        NodeId left  = regex_builder_get_left(b, self);
        NodeId right = regex_builder_get_right(b, self);
        if (regex_builder_get_kind(b, left) == KIND_COMPL
            && nodeid_eq(regex_builder_get_left(b, left), NODE_ID_TOPPLUS)) {
            return nodeid_eq(right, NODE_ID_END);
        }
    }
    return false;
}

bool
nodeid_is_ts(NodeId self)
{
    return nodeid_eq(NODE_ID_TS, self);
}

bool
nodeid_is_pred_star(NodeId self, const RegexBuilder *b, NodeId *out)
{
    if (nodeid_eq(NODE_ID_EPS, self)) return false;
    if (nodeid_is_star(self, b) && nodeid_is_pred(regex_builder_get_left(b, self), b)) {
        *out = regex_builder_get_left(b, self);
        return true;
    }
    return false;
}

bool
nodeid_is_contains(NodeId self, const RegexBuilder *b, NodeId *out)
{
    if (nodeid_is_concat(self, b)
        && nodeid_eq(regex_builder_get_left(b, self), NODE_ID_TS)) {
        NodeId middle = regex_builder_get_right(b, self);
        if (regex_builder_get_kind(b, middle) == KIND_CONCAT
            && nodeid_eq(regex_builder_get_right(b, middle), NODE_ID_TS)) {
            *out = regex_builder_get_left(b, middle);
            return true;
        }
    }
    return false;
}

bool
nodeid_has_concat_tail(NodeId self, const RegexBuilder *b, NodeId tail)
{
    if (nodeid_eq(self, tail)) return true;
    if (nodeid_is_kind(self, b, KIND_CONCAT)) {
        return nodeid_has_concat_tail(nodeid_right(self, b), b, tail);
    }
    return false;
}

// Iterators / predicates over union/inter trees.
typedef void (*NodeIdCallback)(RegexBuilder *b, NodeId n, void *ctx);
typedef bool (*NodeIdPredCallback)(RegexBuilder *b, NodeId n, void *ctx);
typedef bool (*NodeIdReadPredCallback)(NodeId n, void *ctx);

static void
nodeid_iter_union(NodeId self, RegexBuilder *b, NodeIdCallback f, void *ctx)
{
    NodeId curr = self;
    while (regex_builder_get_kind(b, curr) == KIND_UNION) {
        f(b, regex_builder_get_left(b, curr), ctx);
        curr = regex_builder_get_right(b, curr);
    }
    f(b, curr, ctx);
}

static bool
nodeid_any_inter_component(NodeId self, const RegexBuilder *b,
                           NodeIdReadPredCallback f, void *ctx)
{
    NodeId cur = self;
    while (regex_builder_get_kind(b, cur) == KIND_INTER) {
        if (f(regex_builder_get_left(b, cur), ctx)) return true;
        cur = regex_builder_get_right(b, cur);
    }
    return f(cur, ctx);
}

static bool
nodeid_any_union_component(NodeId self, const RegexBuilder *b,
                           NodeIdReadPredCallback f, void *ctx)
{
    NodeId cur = self;
    while (regex_builder_get_kind(b, cur) == KIND_UNION) {
        if (f(regex_builder_get_left(b, cur), ctx)) return true;
        cur = regex_builder_get_right(b, cur);
    }
    return f(cur, ctx);
}

// ============================================================================
// RegexBuilder constructor / accessors.
// ============================================================================

const Solver *
regex_builder_solver_ref(const RegexBuilder *b)
{
    return b->mb.solver;
}

Solver *
regex_builder_solver(RegexBuilder *b)
{
    return b->mb.solver;
}

/* Bound on the algebra's TRegex state.  Each entry is 16 bytes; the cap
 * itself is small but every `regex_builder_mk_binary` call reallocates
 * the `mk_binary_memo` dict, so growth in `tr_array` correlates with a
 * far larger pool footprint via the memo / tr_cache fan-out.  Adversarial
 * intersection patterns drove unbounded growth into multi-GB territory
 * and stalled the GC scan; 5000 keeps the worst case bounded to a few MB
 * while still covering every fixture in `prefix.toml` that compiles
 * cleanly today.  (The compile path uses an in-place dict clear on the
 * memo and a sticky error latch on the builder; both are wired together
 * so a single MISSING return propagates the error out without further
 * state expansion.) */
#define N00B_REGEX_TR_ARRAY_CAP 500000

static TRegexId
regex_builder_tr_init(RegexBuilder *self, TRegex_TSetId inst)
{
    if (self->state_space_err
        || self->tr_array.len >= N00B_REGEX_TR_ARRAY_CAP) {
        self->state_space_err = true;
        return TREGEX_ID_MISSING;
    }
    TRegexId new_id = (TRegexId){ (uint32_t)(self->tr_array.len) };
    // The TRegex `tr_cache` indexes the heap-stable copy of `inst` we make
    // inside tregex_map_insert.  Insert first (cache lookup) then push.
    tregex_map_insert(self->tr_cache, inst, new_id, self->allocator);
    VecTRegex_push(&self->tr_array, inst, self->allocator);
    return new_id;
}

static TRegexId
regex_builder_get_tregex_id(RegexBuilder *self, TRegex_TSetId inst)
{
    TRegexId id;
    if (tregex_map_get(self->tr_cache, &inst, &id)) return id;
    return regex_builder_tr_init(self, inst);
}

static const TRegex_TSetId *
regex_builder_get_tregex(const RegexBuilder *self, TRegexId inst)
{
    n00b_require((size_t)inst.v < self->tr_array.len,
                 "TRegexId out of bounds");
    return &self->tr_array.data[inst.v];
}

NodeId
regex_builder_get_left(const RegexBuilder *self, NodeId node_id)
{
    n00b_require((size_t)node_id.v < self->array.len, "NodeId out of bounds");
    return self->array.data[node_id.v].left;
}

NodeId
regex_builder_get_right(const RegexBuilder *self, NodeId node_id)
{
    n00b_require((size_t)node_id.v < self->array.len, "NodeId out of bounds");
    return self->array.data[node_id.v].right;
}

uint32_t
regex_builder_get_extra(const RegexBuilder *self, NodeId node_id)
{
    n00b_require((size_t)node_id.v < self->array.len, "NodeId out of bounds");
    return self->array.data[node_id.v].extra;
}

Kind
regex_builder_get_kind(const RegexBuilder *self, NodeId node_id)
{
    n00b_require((size_t)node_id.v < self->array.len, "NodeId out of bounds");
    return (Kind)self->array.data[node_id.v].kind;
}

void
regex_builder_set_lookahead_context_max(RegexBuilder *self, uint32_t v)
{
    self->lookahead_context_max = v;
}

NodeId
regex_builder_get_lookahead_inner(const RegexBuilder *self, NodeId nid)
{
    return regex_builder_get_left(self, nid);
}

NodeId
regex_builder_get_lookahead_tail(const RegexBuilder *self, NodeId nid)
{
    return regex_builder_get_right(self, nid);
}

uint32_t
regex_builder_get_lookahead_rel(const RegexBuilder *self, NodeId nid)
{
    return regex_builder_get_extra(self, nid);
}

NodeId
regex_builder_get_lookbehind_inner(const RegexBuilder *self, NodeId nid)
{
    return regex_builder_get_left(self, nid);
}

NodeId
regex_builder_get_lookbehind_prev(const RegexBuilder *self, NodeId nid)
{
    return regex_builder_get_right(self, nid);
}

const NodeKey *
regex_builder_get_node(const RegexBuilder *self, NodeId nid)
{
    n00b_require((size_t)nid.v < self->array.len, "NodeId out of bounds");
    return &self->array.data[nid.v];
}

MetadataId
regex_builder_get_node_meta_id(RegexBuilder *self, NodeId n)
{
    n00b_require((size_t)n.v < self->metadata.len,
                 "NodeId out of bounds (metadata)");
    return self->metadata.data[n.v];
}

static const Metadata *
regex_builder_get_meta(const RegexBuilder *self, NodeId node_id)
{
    n00b_require((size_t)node_id.v < self->metadata.len,
                 "NodeId out of bounds (metadata)");
    MetadataId meta_id = self->metadata.data[node_id.v];
    n00b_require((size_t)meta_id.v < self->mb.array.len,
                 "MetadataId out of bounds");
    return &self->mb.array.data[meta_id.v];
}

NullsId
regex_builder_get_nulls_id(const RegexBuilder *self, NodeId node_id)
{
    if (nodeid_eq(node_id, NODE_ID_MISSING)) return NULLS_ID_EMPTY;
    return regex_builder_get_meta(self, node_id)->nulls;
}

NullsId
regex_builder_center_nulls_id(RegexBuilder *self, NullsId nid)
{
    return nulls_builder_and_mask(&self->mb.nb, nid, NULLABILITY_CENTER);
}

NullsId
regex_builder_get_nulls_id_w_mask(RegexBuilder *self, NodeId node_id, Nullability mask)
{
    if (nodeid_eq(node_id, NODE_ID_MISSING)) return NULLS_ID_EMPTY;
    NullsId nulls = regex_builder_get_meta(self, node_id)->nulls;
    return nulls_builder_and_mask(&self->mb.nb, nulls, mask);
}

MetaFlags
regex_builder_get_meta_flags(const RegexBuilder *self, NodeId node_id)
{
    n00b_require((size_t)node_id.v < self->metadata.len,
                 "NodeId out of bounds (metadata)");
    MetadataId meta_id = self->metadata.data[node_id.v];
    return self->mb.array.data[meta_id.v].flags;
}

Nullability
regex_builder_get_only_nullability(const RegexBuilder *self, NodeId node_id)
{
    return metaflags_nullability(regex_builder_get_meta(self, node_id)->flags);
}

MetaFlags
regex_builder_get_flags_contains(const RegexBuilder *self, NodeId node_id)
{
    n00b_require((size_t)node_id.v < self->metadata.len,
                 "NodeId out of bounds (metadata)");
    MetadataId meta_id = self->metadata.data[node_id.v];
    return metaflags_all_contains_flags(self->mb.array.data[meta_id.v].flags);
}

TSetId
regex_builder_pred_tset(const RegexBuilder *b, NodeId n)
{
    n00b_require((size_t)n.v < b->array.len, "NodeId out of bounds");
    return (TSetId){ b->array.data[n.v].extra };
}

bool
regex_builder_contains_lookbehind(NodeId n, RegexBuilder *b)
{
    return metaflags_has(regex_builder_get_meta_flags(b, n),
                         METAFLAGS_CONTAINS_LOOKBEHIND);
}

bool
regex_builder_contains_look(const RegexBuilder *self, NodeId node_id)
{
    return metaflags_has(regex_builder_get_meta_flags(self, node_id),
        metaflags_or(METAFLAGS_CONTAINS_LOOKBEHIND, METAFLAGS_CONTAINS_LOOKAHEAD));
}

bool
regex_builder_contains_anchors(const RegexBuilder *self, NodeId node_id)
{
    return metaflags_has(regex_builder_get_meta_flags(self, node_id),
                         METAFLAGS_CONTAINS_ANCHORS);
}

bool
regex_builder_is_infinite(const RegexBuilder *self, NodeId node_id)
{
    return metaflags_has(regex_builder_get_meta_flags(self, node_id),
                         METAFLAGS_INFINITE_LENGTH);
}

NodeId
regex_builder_left(const RegexBuilder *b, NodeId n)
{
    return regex_builder_get_left(b, n);
}

NodeId
regex_builder_right(const RegexBuilder *b, NodeId n)
{
    return regex_builder_get_right(b, n);
}

NodeId
regex_builder_node_left(RegexBuilder *b, NodeId n)
{
    return regex_builder_get_left(b, n);
}

NodeId
regex_builder_node_right(RegexBuilder *b, NodeId n)
{
    return regex_builder_get_right(b, n);
}

// ============================================================================
// regex_builder_new — pre-interns sentinel ids in fixed order.
// ============================================================================

n00b_allocator_t *
regex_builder_allocator(const RegexBuilder *self)
{
    return self ? self->allocator : nullptr;
}

RegexBuilder *
regex_builder_new(n00b_allocator_t *allocator)
{
    RegexBuilder *inst = n00b_alloc_with_opts(
        RegexBuilder, &(n00b_alloc_opts_t){.allocator = allocator});
    inst->allocator    = allocator;
    inst->mb           = metadata_builder_new(allocator);
    inst->array        = (VecNodeKey){};
    inst->index        = n00b_alloc_with_opts(
        NodeKeyMap, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(inst->index, .skip_obj_hash = true, .allocator = allocator,
                   .scan_kind = N00B_GC_SCAN_KIND_NONE);
    inst->cache_empty  = n00b_alloc_with_opts(
        NodeFlagsMap, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(inst->cache_empty, .skip_obj_hash = true,
                   .allocator = allocator,
                   .scan_kind = N00B_GC_SCAN_KIND_NONE);
    inst->tr_array     = (VecTRegex){};
    inst->tr_cache     = n00b_alloc_with_opts(
        TRegexMap, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(inst->tr_cache,
                   .hash          = tregex_ptr_hash,
                   .skip_obj_hash = false,
                   .allocator     = allocator);
    inst->flags        = BUILDER_FLAGS_ZERO;
    inst->lookahead_context_max = 800;
    inst->num_created  = 0;
    inst->metadata     = (VecMetadataId){};
    inst->reversed     = (VecNodeId){};
    inst->tr_der_center = (VecTRegexId){};
    inst->tr_der_begin  = (VecTRegexId){};
    inst->temp_vec     = (VecNodeId){};
    inst->mk_binary_memo = n00b_alloc_with_opts(
        PairTRMap, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(inst->mk_binary_memo, .skip_obj_hash = true,
                   .allocator = allocator,
                   .scan_kind = N00B_GC_SCAN_KIND_NONE);
    inst->clean_cache  = n00b_alloc_with_opts(
        PairTSetTRMap, &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(inst->clean_cache, .skip_obj_hash = true,
                   .allocator = allocator,
                   .scan_kind = N00B_GC_SCAN_KIND_NONE);

    NodeKey def = (NodeKey){
        .kind = KIND_PRED, .left = NODE_ID_MISSING,
        .right = NODE_ID_MISSING, .extra = 0,
    };
    VecNodeKey_push(&inst->array, def, inst->allocator);
    (void)regex_builder_mk_pred(inst, TSET_ID_EMPTY);
    (void)regex_builder_mk_star(inst, NODE_ID_BOT);
    (void)regex_builder_mk_pred(inst, TSET_ID_FULL);
    (void)regex_builder_mk_star(inst, NODE_ID_TOP);
    (void)regex_builder_mk_plus(inst, NODE_ID_TOP);
    (void)regex_builder_mk_unset(inst, KIND_BEGIN);
    (void)regex_builder_mk_unset(inst, KIND_END);

    TRegex_TSetId t0 = n00b_variant_set(TRegex_TSetId, TRegex_leaf_t, ((TRegex_leaf_t){ .leaf = NODE_ID_MISSING }));
    VecTRegex_push(&inst->tr_array, t0, inst->allocator);
    (void)regex_builder_mk_leaf(inst, NODE_ID_BOT);
    (void)regex_builder_mk_leaf(inst, NODE_ID_EPS);
    (void)regex_builder_mk_leaf(inst, NODE_ID_TOP);
    (void)regex_builder_mk_leaf(inst, NODE_ID_TS);

    inst->flags = BUILDER_FLAGS_SUBSUME;
    return inst;
}

// ============================================================================
// TRegex builders (mk_leaf, mk_ite, clean) and the unary/binary lifters.
// ============================================================================

static TRegexId
regex_builder_mk_leaf(RegexBuilder *self, NodeId node_id)
{
    TRegex_TSetId t = n00b_variant_set(TRegex_TSetId, TRegex_leaf_t, ((TRegex_leaf_t){ .leaf = node_id }));
    return regex_builder_get_tregex_id(self, t);
}

static TRegexId regex_builder_clean(RegexBuilder *self, TSetId beta, TRegexId tterm);

static TRegexId
regex_builder_mk_ite(RegexBuilder *self, TSetId cond,
                     TRegexId then_id, TRegexId else_id)
{
    TRegex_TSetId tmp = n00b_variant_set(TRegex_TSetId, TRegex_ite_t, ((TRegex_ite_t){ .set = cond, .then_id = then_id, .else_id = else_id }));
    TRegexId cached;
    if (tregex_map_get(self->tr_cache, &tmp, &cached)) return cached;
    if (tregex_id_eq(then_id, else_id)) return then_id;
    if (solver_is_full_id(self->mb.solver, cond))  return then_id;
    if (solver_is_empty_id(self->mb.solver, cond)) return else_id;

    TRegexId clean_then;
    if (n00b_variant_is_type(self->tr_array.data[then_id.v], TRegex_leaf_t)) {
        clean_then = then_id;
    }
    else {
        clean_then = regex_builder_clean(self, cond, then_id);
    }
    TSetId notcond = solver_not_id(self->mb.solver, cond);
    TRegexId clean_else;
    if (n00b_variant_is_type(self->tr_array.data[else_id.v], TRegex_leaf_t)) {
        clean_else = else_id;
    }
    else {
        clean_else = regex_builder_clean(self, notcond, else_id);
    }
    if (tregex_id_eq(clean_then, clean_else)) return clean_then;

    {
        const TRegex_TSetId *t = regex_builder_get_tregex(self, clean_then);
        if (n00b_variant_is_type(*t, TRegex_ite_t)
            && tregex_id_eq(n00b_variant_get(*t, TRegex_ite_t).else_id, clean_else)) {
            TRegex_ite_t _a   = n00b_variant_get(*t, TRegex_ite_t);
            TSetId   leftcond = _a.set;
            TRegexId new_then = _a.then_id;
            TSetId   sand     = solver_and_id(self->mb.solver, cond, leftcond);
            return regex_builder_mk_ite(self, sand, new_then, clean_else);
        }
    }
    {
        const TRegex_TSetId *t = regex_builder_get_tregex(self, clean_else);
        if (n00b_variant_is_type(*t, TRegex_ite_t)
            && tregex_id_eq(n00b_variant_get(*t, TRegex_ite_t).then_id, clean_then)) {
            TRegex_ite_t _a   = n00b_variant_get(*t, TRegex_ite_t);
            TRegexId e2clone  = _a.else_id;
            TSetId   c2       = _a.set;
            TSetId   new_cond = solver_or_id(self->mb.solver, cond, c2);
            return regex_builder_mk_ite(self, new_cond, clean_then, e2clone);
        }
    }

    if (tregex_id_eq(clean_then, TREGEX_ID_BOT)) {
        TSetId flip_cond = solver_not_id(self->mb.solver, cond);
        TRegex_TSetId t  = n00b_variant_set(TRegex_TSetId, TRegex_ite_t, ((TRegex_ite_t){ .set = flip_cond, .then_id = clean_else, .else_id = clean_then }));
        return regex_builder_get_tregex_id(self, t);
    }

    TRegex_TSetId t = n00b_variant_set(TRegex_TSetId, TRegex_ite_t, ((TRegex_ite_t){ .set = cond, .then_id = clean_then, .else_id = clean_else }));
    return regex_builder_get_tregex_id(self, t);
}

static bool
regex_builder_unsat(RegexBuilder *self, TSetId c1, TSetId c2)
{
    return !solver_is_sat_id(self->mb.solver, c1, c2);
}

static TRegexId
regex_builder_clean(RegexBuilder *self, TSetId beta, TRegexId tterm)
{
    TRegexId cached;
    PairTSetTR k = (PairTSetTR){ beta, tterm };
    if (pair_tset_tr_map_get(self->clean_cache, k, &cached)) return cached;
    TRegexId result;
    TRegex_TSetId t = self->tr_array.data[tterm.v];
    if (n00b_variant_is_type(t, TRegex_leaf_t)) {
        result = tterm;
    }
    else {
        TRegex_ite_t _t   = n00b_variant_get(t, TRegex_ite_t);
        TSetId   alpha    = _t.set;
        TRegexId then_id  = _t.then_id;
        TRegexId else_id  = _t.else_id;
        TSetId   notalpha = solver_not_id(self->mb.solver, alpha);
        if (solver_unsat_id(self->mb.solver, beta, alpha)) {
            result = regex_builder_clean(self, beta, else_id);
        }
        else if (regex_builder_unsat(self, beta, notalpha)) {
            result = regex_builder_clean(self, beta, then_id);
        }
        else {
            TSetId   tc       = solver_and_id(self->mb.solver, beta, alpha);
            TSetId   ec       = solver_and_id(self->mb.solver, beta, notalpha);
            TRegexId new_then = regex_builder_clean(self, tc, then_id);
            TRegexId new_else = regex_builder_clean(self, ec, else_id);
            result            = regex_builder_mk_ite(self, alpha, new_then, new_else);
        }
    }
    pair_tset_tr_map_insert(self->clean_cache, k, result);
    return result;
}

typedef NodeId (*UnaryApply)(RegexBuilder *b, NodeId n, void *ctx);
typedef NodeId (*BinaryApply)(RegexBuilder *b, NodeId l, NodeId r, void *ctx);
typedef n00b_regex_algebra_err_t (*BinaryApplyResult)(RegexBuilder *b, NodeId l, NodeId r,
                                                      void *ctx, NodeId *out);

static TRegexId
regex_builder_mk_unary(RegexBuilder *self, TRegexId term,
                       UnaryApply apply, void *ctx)
{
    if (self->state_space_err) return TREGEX_ID_MISSING;
    TRegex_TSetId t = self->tr_array.data[term.v];
    if (n00b_variant_is_type(t, TRegex_leaf_t)) {
        NodeId applied = apply(self, n00b_variant_get(t, TRegex_leaf_t).leaf, ctx);
        return regex_builder_mk_leaf(self, applied);
    }
    TRegex_ite_t _t = n00b_variant_get(t, TRegex_ite_t);
    TRegexId t1 = regex_builder_mk_unary(self, _t.then_id, apply, ctx);
    TRegexId e1 = regex_builder_mk_unary(self, _t.else_id, apply, ctx);
    return regex_builder_mk_ite(self, _t.set, t1, e1);
}

static n00b_regex_algebra_err_t
regex_builder_mk_binary_result(RegexBuilder *self, TRegexId left, TRegexId right,
                               BinaryApplyResult apply, void *ctx, TRegexId *out)
{
    TRegex_TSetId tl = self->tr_array.data[left.v];
    if (n00b_variant_is_type(tl, TRegex_leaf_t)) {
        TRegex_TSetId tr = self->tr_array.data[right.v];
        if (n00b_variant_is_type(tr, TRegex_leaf_t)) {
            NodeId applied; n00b_regex_algebra_err_t e;
            e = apply(self, n00b_variant_get(tl, TRegex_leaf_t).leaf, n00b_variant_get(tr, TRegex_leaf_t).leaf, ctx, &applied);
            if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
            *out = regex_builder_mk_leaf(self, applied);
            return N00B_REGEX_ALGEBRA_ERR_NONE;
        }
        TRegex_ite_t _r = n00b_variant_get(tr, TRegex_ite_t);
        TRegexId t2, e2; n00b_regex_algebra_err_t e;
        e = regex_builder_mk_binary_result(self, left, _r.then_id, apply, ctx, &t2);
        if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
        e = regex_builder_mk_binary_result(self, left, _r.else_id, apply, ctx, &e2);
        if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
        *out = regex_builder_mk_ite(self, _r.set, t2, e2);
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    TRegex_TSetId tr = self->tr_array.data[right.v];
    if (n00b_variant_is_type(tr, TRegex_leaf_t)) {
        TRegex_ite_t _l = n00b_variant_get(tl, TRegex_ite_t);
        TRegexId t2, e2; n00b_regex_algebra_err_t e;
        e = regex_builder_mk_binary_result(self, _l.then_id, right, apply, ctx, &t2);
        if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
        e = regex_builder_mk_binary_result(self, _l.else_id, right, apply, ctx, &e2);
        if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
        *out = regex_builder_mk_ite(self, _l.set, t2, e2);
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    TRegex_ite_t _l = n00b_variant_get(tl, TRegex_ite_t);
    TRegex_ite_t _r = n00b_variant_get(tr, TRegex_ite_t);
    if (_l.set.v == _r.set.v) {
        TRegexId t2, e2; n00b_regex_algebra_err_t e;
        e = regex_builder_mk_binary_result(self, _l.then_id, _r.then_id, apply, ctx, &t2);
        if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
        e = regex_builder_mk_binary_result(self, _l.else_id, _r.else_id, apply, ctx, &e2);
        if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
        *out = regex_builder_mk_ite(self, _l.set, t2, e2);
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    if (_l.set.v > _r.set.v) {
        TRegexId t2, e2; n00b_regex_algebra_err_t e;
        e = regex_builder_mk_binary_result(self, _l.then_id, right, apply, ctx, &t2);
        if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
        e = regex_builder_mk_binary_result(self, _l.else_id, right, apply, ctx, &e2);
        if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
        *out = regex_builder_mk_ite(self, _l.set, t2, e2);
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    TRegexId t2, e2; n00b_regex_algebra_err_t e;
    e = regex_builder_mk_binary_result(self, left, _r.then_id, apply, ctx, &t2);
    if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
    e = regex_builder_mk_binary_result(self, left, _r.else_id, apply, ctx, &e2);
    if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
    *out = regex_builder_mk_ite(self, _r.set, t2, e2);
    return N00B_REGEX_ALGEBRA_ERR_NONE;
}

static TRegexId regex_builder_mk_binary_inner(RegexBuilder *self, TRegexId left,
                                              TRegexId right, BinaryApply apply,
                                              void *ctx);

static NodeId
mk_binary_unary_thunk(RegexBuilder *b, NodeId n, void *ctx)
{
    struct { BinaryApply f; void *user; } *cb = ctx;
    return cb->f(b, n, n, cb->user);
}

static TRegexId
regex_builder_mk_binary(RegexBuilder *self, TRegexId left,
                        TRegexId right, BinaryApply apply, void *ctx)
{
    if (self->state_space_err) return TREGEX_ID_MISSING;
    /* The memo is per-top-level-binary-call: nothing produced by an
     * earlier mk_binary call (different apply / different operands) is
     * valid for the next.  Previously we allocated a fresh dict each
     * call (~1 KB bucket/key/value storage) which compounded into
     * multi-GB heap on adversarial intersection patterns.  Clearing the
     * existing dict in-place keeps the per-call cost to an O(buckets)
     * memset. */
    if (self->mk_binary_memo == nullptr) {
        self->mk_binary_memo = n00b_alloc_with_opts(
            PairTRMap, &(n00b_alloc_opts_t){.allocator = self->allocator});
        n00b_dict_init(self->mk_binary_memo, .skip_obj_hash = true,
                       .allocator = self->allocator,
                       .scan_kind = N00B_GC_SCAN_KIND_NONE);
    } else {
        n00b_dict_clear(self->mk_binary_memo);
    }
    return regex_builder_mk_binary_inner(self, left, right, apply, ctx);
}

static TRegexId
regex_builder_mk_binary_inner(RegexBuilder *self, TRegexId left,
                              TRegexId right, BinaryApply apply, void *ctx)
{
    /* Short-circuit the moment the state-space cap has been latched —
     * otherwise recursion keeps walking the tr_array while every leaf
     * call returns MISSING, wasting time on a doomed compile. */
    if (self->state_space_err) return TREGEX_ID_MISSING;
    if (tregex_id_eq(left, right)) {
        struct { BinaryApply f; void *user; } cb = { apply, ctx };
        return regex_builder_mk_unary(self, left, mk_binary_unary_thunk, &cb);
    }
    PairTR k = (PairTR){ left, right };
    TRegexId cached;
    if (pair_tr_map_get(self->mk_binary_memo, k, &cached)) return cached;

    TRegexId result;
    TRegex_TSetId tl = self->tr_array.data[left.v];
    TRegex_TSetId tr = self->tr_array.data[right.v];
    if (n00b_variant_is_type(tl, TRegex_leaf_t)) {
        if (n00b_variant_is_type(tr, TRegex_leaf_t)) {
            NodeId applied = apply(self, n00b_variant_get(tl, TRegex_leaf_t).leaf, n00b_variant_get(tr, TRegex_leaf_t).leaf, ctx);
            result = regex_builder_mk_leaf(self, applied);
        }
        else {
            TRegex_ite_t _r = n00b_variant_get(tr, TRegex_ite_t);
            TRegexId t2 = regex_builder_mk_binary_inner(self, left, _r.then_id, apply, ctx);
            TRegexId e2 = regex_builder_mk_binary_inner(self, left, _r.else_id, apply, ctx);
            result = regex_builder_mk_ite(self, _r.set, t2, e2);
        }
    }
    else if (n00b_variant_is_type(tr, TRegex_leaf_t)) {
        TRegex_ite_t _l = n00b_variant_get(tl, TRegex_ite_t);
        TRegexId t2 = regex_builder_mk_binary_inner(self, _l.then_id, right, apply, ctx);
        TRegexId e2 = regex_builder_mk_binary_inner(self, _l.else_id, right, apply, ctx);
        result = regex_builder_mk_ite(self, _l.set, t2, e2);
    }
    else if (n00b_variant_get(tl, TRegex_ite_t).set.v == n00b_variant_get(tr, TRegex_ite_t).set.v) {
        TRegex_ite_t _l = n00b_variant_get(tl, TRegex_ite_t);
        TRegex_ite_t _r = n00b_variant_get(tr, TRegex_ite_t);
        TRegexId t = regex_builder_mk_binary_inner(self, _l.then_id, _r.then_id, apply, ctx);
        TRegexId e = regex_builder_mk_binary_inner(self, _l.else_id, _r.else_id, apply, ctx);
        result = regex_builder_mk_ite(self, _l.set, t, e);
    }
    else if (n00b_variant_get(tl, TRegex_ite_t).set.v > n00b_variant_get(tr, TRegex_ite_t).set.v) {
        TRegex_ite_t _l = n00b_variant_get(tl, TRegex_ite_t);
        TRegexId t = regex_builder_mk_binary_inner(self, _l.then_id, right, apply, ctx);
        TRegexId e = regex_builder_mk_binary_inner(self, _l.else_id, right, apply, ctx);
        result = regex_builder_mk_ite(self, _l.set, t, e);
    }
    else {
        TRegex_ite_t _r = n00b_variant_get(tr, TRegex_ite_t);
        TRegexId t = regex_builder_mk_binary_inner(self, left, _r.then_id, apply, ctx);
        TRegexId e = regex_builder_mk_binary_inner(self, left, _r.else_id, apply, ctx);
        result = regex_builder_mk_ite(self, _r.set, t, e);
    }
    pair_tr_map_insert(self->mk_binary_memo, k, result);
    return result;
}

// ============================================================================
// get_nulls — pushes (mask, pending_rel) into a Nulls accumulator.
// ============================================================================

void
regex_builder_get_nulls(RegexBuilder *self, uint32_t pending_rel, Nullability mask,
                        Nulls *acc, NodeId node_id)
{
    if (!regex_builder_is_nullable(self, node_id, mask)) return;
    Kind k = regex_builder_get_kind(self, node_id);
    switch (k) {
    case KIND_PRED: break;
    case KIND_END:
        if (nullability_has(mask, NULLABILITY_END)) {
            null_state_set_insert(acc,
                null_state_new(nullability_and(mask, NULLABILITY_END), pending_rel));
        }
        break;
    case KIND_BEGIN:
        if (nullability_has(mask, NULLABILITY_BEGIN)) {
            null_state_set_insert(acc,
                null_state_new(nullability_and(mask, NULLABILITY_BEGIN), pending_rel));
        }
        break;
    case KIND_CONCAT: {
        Nullability new_mask = nullability_and(regex_builder_nullability(self, node_id), mask);
        regex_builder_get_nulls(self, pending_rel, new_mask, acc, nodeid_left(node_id, self));
        if (regex_builder_is_nullable(self, nodeid_left(node_id, self), mask)) {
            regex_builder_get_nulls(self, pending_rel, new_mask, acc, nodeid_right(node_id, self));
        }
        break;
    }
    case KIND_UNION:
        regex_builder_get_nulls(self, pending_rel, mask, acc, nodeid_left(node_id, self));
        regex_builder_get_nulls(self, pending_rel, mask, acc, nodeid_right(node_id, self));
        break;
    case KIND_INTER: {
        Nullability new_mask = nullability_and(regex_builder_nullability(self, node_id), mask);
        regex_builder_get_nulls(self, pending_rel, new_mask, acc, nodeid_left(node_id, self));
        regex_builder_get_nulls(self, pending_rel, new_mask, acc, nodeid_right(node_id, self));
        break;
    }
    case KIND_STAR:
        null_state_set_insert(acc, null_state_new(mask, pending_rel));
        regex_builder_get_nulls(self, pending_rel, mask, acc, nodeid_left(node_id, self));
        break;
    case KIND_COMPL:
        if (!regex_builder_is_nullable(self, nodeid_left(node_id, self), mask)) {
            null_state_set_insert(acc, null_state_new(mask, 0));
        }
        break;
    case KIND_LOOKBEHIND: {
        Nullability new_mask = nullability_and(regex_builder_nullability(self, node_id), mask);
        regex_builder_get_nulls(self, pending_rel, new_mask, acc, nodeid_left(node_id, self));
        if (!nodeid_eq(nodeid_right(node_id, self), NODE_ID_MISSING)) {
            regex_builder_get_nulls(self, pending_rel, new_mask, acc, nodeid_right(node_id, self));
        }
        break;
    }
    case KIND_LOOKAHEAD: {
        NodeId la_inner = regex_builder_get_lookahead_inner(self, node_id);
        if (regex_builder_is_nullable(self, la_inner, mask)) {
            uint32_t rel = regex_builder_get_lookahead_rel(self, node_id);
            if (rel != UINT32_MAX) {
                regex_builder_get_nulls(self, pending_rel + rel, mask, acc, la_inner);
            }
            NodeId la_tail = regex_builder_get_lookahead_tail(self, node_id);
            if (!nodeid_eq(la_tail, NODE_ID_MISSING)) {
                regex_builder_get_nulls(self, pending_rel, mask, acc, la_tail);
            }
        }
        break;
    }
    case KIND_COUNTED: {
        uint32_t packed = regex_builder_get_extra(self, node_id);
        uint32_t best   = packed >> 16;
        if (best > 0) {
            null_state_set_insert(acc,
                null_state_new(mask, pending_rel + best));
        }
        break;
    }
    }
}

// ============================================================================
// MinMax / fixed_length / starts_with_ts / ends_with_ts.
// ============================================================================

static MinMax regex_builder_get_bounded_length(const RegexBuilder *self, NodeId node_id);
static uint32_t regex_builder_get_min_length_only(const RegexBuilder *self, NodeId node_id);

static uint32_t
saturating_add_u32(uint32_t a, uint32_t b)
{
    uint32_t r = a + b;
    return (r < a) ? UINT32_MAX : r;
}

static uint32_t u32_min(uint32_t a, uint32_t b) { return a < b ? a : b; }
static uint32_t u32_max(uint32_t a, uint32_t b) { return a > b ? a : b; }

uint32_t
regex_builder_max_lookahead_body_len(const RegexBuilder *self, NodeId node_id)
{
    NodeFlagsMap *visited = n00b_alloc_with_opts(
        NodeFlagsMap, &(n00b_alloc_opts_t){.allocator = self->allocator});
    n00b_dict_init(visited, .skip_obj_hash = true, .allocator = self->allocator,
                   .scan_kind = N00B_GC_SCAN_KIND_NONE);
    VecNodeId stack = (VecNodeId){};
    VecNodeId_push(&stack, node_id, self->allocator);
    uint32_t best = 0;
    while (stack.len > 0) {
        NodeId n = stack.data[--stack.len];
        if (nodeid_eq(n, NODE_ID_MISSING)) continue;
        NodeFlags ignored;
        if (node_flags_map_get(visited, n, &ignored)) continue;
        node_flags_map_insert(visited, n, NODE_FLAGS_ZERO);
        Kind k = regex_builder_get_kind(self, n);
        if (k == KIND_LOOKAHEAD) {
            NodeId body = regex_builder_get_lookahead_inner(self, n);
            if (nodeid_is_concat(body, self)
                && nodeid_eq(nodeid_right(body, self), NODE_ID_TS)) {
                body = nodeid_left(body, self);
            }
            MinMax mm = regex_builder_get_min_max_length(self, body);
            if (mm.max > best) best = mm.max;
        }
        switch (k) {
        case KIND_PRED: case KIND_BEGIN: case KIND_END: break;
        case KIND_STAR: case KIND_COMPL:
            VecNodeId_push(&stack, nodeid_left(n, self), self->allocator);
            break;
        default:
            VecNodeId_push(&stack, nodeid_left(n, self), self->allocator);
            VecNodeId_push(&stack, nodeid_right(n, self), self->allocator);
            break;
        }
    }
    if (stack.data) n00b_free(stack.data);
    return best;
}

MinMax
regex_builder_get_min_max_length(const RegexBuilder *self, NodeId node_id)
{
    if (regex_builder_is_infinite(self, node_id)) {
        if (nodeid_is_inter(node_id, self)) {
            return regex_builder_get_bounded_length(self, node_id);
        }
        return (MinMax){ regex_builder_get_min_length_only(self, node_id), UINT32_MAX };
    }
    return regex_builder_get_bounded_length(self, node_id);
}

static MinMax
regex_builder_get_bounded_length(const RegexBuilder *self, NodeId node_id)
{
    if (nodeid_eq(node_id, NODE_ID_EPS)) return (MinMax){ 0, 0 };
    Kind k = regex_builder_get_kind(self, node_id);
    switch (k) {
    case KIND_END: case KIND_BEGIN: return (MinMax){ 0, 0 };
    case KIND_PRED: return (MinMax){ 1, 1 };
    case KIND_CONCAT: {
        MinMax l = regex_builder_get_bounded_length(self, nodeid_left(node_id, self));
        MinMax r = regex_builder_get_bounded_length(self, nodeid_right(node_id, self));
        return (MinMax){ l.min + r.min, saturating_add_u32(l.max, r.max) };
    }
    case KIND_UNION: {
        MinMax l = regex_builder_get_bounded_length(self, nodeid_left(node_id, self));
        MinMax r = regex_builder_get_bounded_length(self, nodeid_right(node_id, self));
        return (MinMax){ u32_min(l.min, r.min), u32_max(l.max, r.max) };
    }
    case KIND_INTER: {
        MinMax l = regex_builder_get_min_max_length(self, nodeid_left(node_id, self));
        MinMax r = regex_builder_get_min_max_length(self, nodeid_right(node_id, self));
        return (MinMax){ u32_max(l.min, r.min), u32_min(l.max, r.max) };
    }
    case KIND_LOOKAHEAD: {
        NodeId body = nodeid_left(node_id, self);
        if (regex_builder_is_infinite(self, body)) return (MinMax){ 0, UINT32_MAX };
        NodeId right = nodeid_right(node_id, self);
        if (nodeid_is_missing(right)) return (MinMax){ 0, 0 };
        return regex_builder_get_min_max_length(self, right);
    }
    case KIND_COUNTED: return (MinMax){ 0, 0 };
    case KIND_STAR: case KIND_LOOKBEHIND: case KIND_COMPL:
        return (MinMax){ 0, UINT32_MAX };
    }
    return (MinMax){ 0, 0 };
}

bool
regex_builder_get_fixed_length(const RegexBuilder *self, NodeId node_id, uint32_t *out)
{
    Kind k = regex_builder_get_kind(self, node_id);
    switch (k) {
    case KIND_END: case KIND_BEGIN: *out = 0; return true;
    case KIND_PRED: *out = 1; return true;
    case KIND_CONCAT: {
        uint32_t l, r;
        if (!regex_builder_get_fixed_length(self, nodeid_left(node_id, self), &l)) return false;
        if (!regex_builder_get_fixed_length(self, nodeid_right(node_id, self), &r)) return false;
        *out = l + r; return true;
    }
    case KIND_UNION: {
        uint32_t l, r;
        if (!regex_builder_get_fixed_length(self, nodeid_left(node_id, self), &l)) return false;
        if (!regex_builder_get_fixed_length(self, nodeid_right(node_id, self), &r)) return false;
        if (l == r) { *out = l; return true; }
        return false;
    }
    case KIND_INTER: {
        uint32_t l, r;
        bool hl = regex_builder_get_fixed_length(self, nodeid_left(node_id, self), &l);
        bool hr = regex_builder_get_fixed_length(self, nodeid_right(node_id, self), &r);
        if (hl && hr) { if (l == r) { *out = l; return true; } return false; }
        if (hl) { *out = l; return true; }
        if (hr) { *out = r; return true; }
        return false;
    }
    case KIND_LOOKAHEAD: {
        NodeId right = nodeid_right(node_id, self);
        if (nodeid_is_missing(right)) { *out = 0; return true; }
        return regex_builder_get_fixed_length(self, right, out);
    }
    case KIND_COUNTED: *out = 0; return true;
    case KIND_STAR: case KIND_LOOKBEHIND: case KIND_COMPL: return false;
    }
    return false;
}

static uint32_t
regex_builder_get_min_length_only(const RegexBuilder *self, NodeId node_id)
{
    Kind k = regex_builder_get_kind(self, node_id);
    switch (k) {
    case KIND_END: case KIND_BEGIN: return 0;
    case KIND_PRED: return 1;
    case KIND_CONCAT:
        return regex_builder_get_min_length_only(self, nodeid_left(node_id, self))
             + regex_builder_get_min_length_only(self, nodeid_right(node_id, self));
    case KIND_UNION:
        return u32_min(regex_builder_get_min_length_only(self, nodeid_left(node_id, self)),
                       regex_builder_get_min_length_only(self, nodeid_right(node_id, self)));
    case KIND_INTER:
        return u32_max(regex_builder_get_min_length_only(self, nodeid_left(node_id, self)),
                       regex_builder_get_min_length_only(self, nodeid_right(node_id, self)));
    case KIND_STAR: case KIND_LOOKBEHIND: case KIND_LOOKAHEAD: case KIND_COUNTED:
        return 0;
    case KIND_COMPL:
        return nullability_eq(regex_builder_nullability(self, nodeid_left(node_id, self)),
                              NULLABILITY_NEVER) ? 0 : 1;
    }
    return 0;
}

bool
regex_builder_starts_with_ts(const RegexBuilder *self, NodeId node_id)
{
    if (nodeid_eq(node_id, NODE_ID_TS)) return true;
    Kind k = regex_builder_get_kind(self, node_id);
    switch (k) {
    case KIND_INTER:
    case KIND_UNION:
        return regex_builder_starts_with_ts(self, nodeid_left(node_id, self))
            && regex_builder_starts_with_ts(self, nodeid_right(node_id, self));
    case KIND_CONCAT:
        return regex_builder_starts_with_ts(self, nodeid_left(node_id, self));
    default: return false;
    }
}

bool
regex_builder_ends_with_ts(const RegexBuilder *self, NodeId node_id)
{
    if (nodeid_is_concat(node_id, self)) {
        return regex_builder_ends_with_ts(self, nodeid_right(node_id, self));
    }
    if (nodeid_is_lookahead(node_id, self)) {
        NodeId tail = regex_builder_get_lookahead_tail(self, node_id);
        if (!nodeid_is_missing(tail)) return regex_builder_ends_with_ts(self, tail);
    }
    return nodeid_eq(node_id, NODE_ID_TS);
}

bool
regex_builder_ends_with_ts_any_branch(const RegexBuilder *self, NodeId node_id)
{
    if (nodeid_eq(node_id, NODE_ID_TS)) return true;
    Kind k = regex_builder_get_kind(self, node_id);
    switch (k) {
    case KIND_CONCAT:
        return regex_builder_ends_with_ts_any_branch(self, nodeid_right(node_id, self));
    case KIND_UNION:
        return regex_builder_ends_with_ts_any_branch(self, nodeid_left(node_id, self))
            || regex_builder_ends_with_ts_any_branch(self, nodeid_right(node_id, self));
    case KIND_LOOKAHEAD: {
        NodeId tail = regex_builder_get_lookahead_tail(self, node_id);
        return !nodeid_is_missing(tail) && regex_builder_ends_with_ts_any_branch(self, tail);
    }
    default: return false;
    }
}

bool
regex_builder_is_nullable(RegexBuilder *self, NodeId node_id, Nullability mask)
{
    return (regex_builder_nullability(self, node_id).v & mask.v) != NULLABILITY_NEVER.v;
}

// ============================================================================
// Cached symbolic-derivative bookkeeping + transition_term.
// ============================================================================

TRegexId
regex_builder_cache_der(RegexBuilder *self, NodeId node_id,
                        TRegexId result, Nullability mask)
{
    VecTRegexId *cache = nullability_eq(mask, NULLABILITY_CENTER)
        ? &self->tr_der_center : &self->tr_der_begin;
    while (cache->len <= node_id.v) {
        VecTRegexId_push(cache, TREGEX_ID_MISSING, self->allocator);
    }
    cache->data[node_id.v] = result;
    return result;
}

bool
regex_builder_try_cached_der(RegexBuilder *self, NodeId node_id, Nullability mask,
                             TRegexId *out)
{
    VecTRegexId *cache = nullability_eq(mask, NULLABILITY_CENTER)
        ? &self->tr_der_center : &self->tr_der_begin;
    if ((size_t)node_id.v < cache->len) {
        TRegexId v = cache->data[node_id.v];
        if (!tregex_id_eq(v, TREGEX_ID_MISSING)) {
            *out = v;
            return true;
        }
        return false;
    }
    while (cache->len <= node_id.v) {
        VecTRegexId_push(cache, TREGEX_ID_MISSING, self->allocator);
    }
    return false;
}

NodeId
regex_builder_transition_term(RegexBuilder *self, TRegexId der, TSetId set)
{
    const TRegex_TSetId *term = regex_builder_get_tregex(self, der);
    for (;;) {
        if (n00b_variant_is_type(*term, TRegex_leaf_t)) return n00b_variant_get(*term, TRegex_leaf_t).leaf;
        TRegex_ite_t _t   = n00b_variant_get(*term, TRegex_ite_t);
        TSetId   cond     = _t.set;
        TRegexId then_id  = _t.then_id;
        TRegexId else_id  = _t.else_id;
        if (solver_is_sat_id(self->mb.solver, set, cond)) {
            term = regex_builder_get_tregex(self, then_id);
        }
        else {
            term = regex_builder_get_tregex(self, else_id);
        }
    }
}

// ============================================================================
// Apply-thunks for the binary callback machinery.
// ============================================================================

static NodeId mk_compl_thunk(RegexBuilder *b, NodeId v, [[maybe_unused]] void *ctx)
{
    return regex_builder_mk_compl(b, v);
}

static NodeId mk_inter_thunk(RegexBuilder *b, NodeId l, NodeId r, [[maybe_unused]] void *ctx)
{
    return regex_builder_mk_inter(b, l, r);
}

static NodeId mk_union_thunk(RegexBuilder *b, NodeId l, NodeId r, [[maybe_unused]] void *ctx)
{
    return regex_builder_mk_union(b, l, r);
}

static NodeId mk_concat_thunk(RegexBuilder *b, NodeId l, NodeId r, [[maybe_unused]] void *ctx)
{
    return regex_builder_mk_concat(b, l, r);
}

extern n00b_regex_algebra_err_t regex_builder_mk_lookbehind_internal(RegexBuilder *self, NodeId lb_body, NodeId lb_prev, NodeId *out);

static n00b_regex_algebra_err_t mk_lookbehind_internal_thunk(RegexBuilder *b, NodeId l, NodeId r,
                                                             [[maybe_unused]] void *ctx, NodeId *out)
{
    return regex_builder_mk_lookbehind_internal(b, l, r, out);
}

typedef struct LookaheadCtx { uint32_t rel; } LookaheadCtx;

static NodeId mk_lookahead_thunk(RegexBuilder *b, NodeId left, NodeId right, void *ctx)
{
    LookaheadCtx *c = ctx;
    return regex_builder_mk_lookahead_internal(b, left, right, c->rel);
}

typedef struct CountedCtx {
    NodeId      chain;
    Nullability mask;
    uint16_t    mid_best;
    uint16_t    new_step;
} CountedCtx;

static NodeId mk_counted_thunk(RegexBuilder *b, NodeId new_body, void *ctx)
{
    CountedCtx *c = ctx;
    uint16_t final_best = (regex_builder_is_nullable(b, new_body, c->mask) && c->new_step >= c->mid_best)
        ? c->new_step : c->mid_best;
    uint32_t packed = ((uint32_t)final_best << 16) | (uint32_t)c->new_step;
    return regex_builder_mk_counted(b, new_body, c->chain, packed);
}

// ============================================================================
// regex_builder_der — symbolic Brzozowski derivative.
// ============================================================================

n00b_result_t(TRegexId)
regex_builder_der(RegexBuilder *self, NodeId node_id, Nullability mask)
{
    {
        TRegexId cached;
        if (regex_builder_try_cached_der(self, node_id, mask, &cached)) {
            return n00b_result_ok(TRegexId, cached);
        }
    }
    TRegexId result;
    Kind k = nodeid_kind(node_id, self);
    switch (k) {
    case KIND_COMPL: {
        TRegexId leftd = regex_builder_der(self, nodeid_left(node_id, self), mask)!;
        result = regex_builder_mk_unary(self, leftd, mk_compl_thunk, nullptr);
        break;
    }
    case KIND_INTER: {
        TRegexId leftd  = regex_builder_der(self, nodeid_left(node_id, self), mask)!;
        TRegexId rightd = regex_builder_der(self, nodeid_right(node_id, self), mask)!;
        result = regex_builder_mk_binary(self, leftd, rightd, mk_inter_thunk, nullptr);
        break;
    }
    case KIND_UNION: {
        TRegexId leftd  = regex_builder_der(self, nodeid_left(node_id, self), mask)!;
        TRegexId rightd = regex_builder_der(self, nodeid_right(node_id, self), mask)!;
        result = regex_builder_mk_binary(self, leftd, rightd, mk_union_thunk, nullptr);
        break;
    }
    case KIND_CONCAT: {
        NodeId head = nodeid_left(node_id, self);
        NodeId tail = nodeid_right(node_id, self);
        TRegexId tail_leaf = regex_builder_mk_leaf(self, tail);
        TRegexId head_der = regex_builder_der(self, head, mask)!;
        if (regex_builder_is_nullable(self, head, mask)) {
            TRegexId rightd = regex_builder_der(self, tail, mask)!;
            TRegexId ldr = regex_builder_mk_binary(self, head_der, tail_leaf, mk_concat_thunk, nullptr);
            result = regex_builder_mk_binary(self, ldr, rightd, mk_union_thunk, nullptr);
        }
        else {
            result = regex_builder_mk_binary(self, head_der, tail_leaf, mk_concat_thunk, nullptr);
        }
        break;
    }
    case KIND_STAR: {
        if (nodeid_eq(node_id, NODE_ID_EPS)) {
            result = TREGEX_ID_BOT;
        }
        else {
            NodeId left = nodeid_left(node_id, self);
            TRegexId r_decr_leaf = regex_builder_mk_leaf(self, node_id);
            TRegexId r_der = regex_builder_der(self, left, mask)!;
            result = regex_builder_mk_binary(self, r_der, r_decr_leaf, mk_concat_thunk, nullptr);
        }
        break;
    }
    case KIND_LOOKBEHIND: {
        TRegexId lb_prev_der;
        NodeId lb_prev = regex_builder_get_lookbehind_prev(self, node_id);
        if (nodeid_eq(lb_prev, NODE_ID_MISSING)) {
            lb_prev_der = TREGEX_ID_MISSING;
        }
        else {
            lb_prev_der = regex_builder_der(self, lb_prev, mask)!;
        }
        NodeId lb_inner = regex_builder_get_lookbehind_inner(self, node_id);
        TRegexId lb_inner_der = regex_builder_der(self, lb_inner, mask)!;
        n00b_regex_algebra_err_t e = regex_builder_mk_binary_result(self, lb_inner_der, lb_prev_der,
                                                                    mk_lookbehind_internal_thunk, nullptr, &result);
        if (e != N00B_REGEX_ALGEBRA_ERR_NONE) {
            return n00b_result_err(TRegexId, e);
        }
        break;
    }
    case KIND_LOOKAHEAD: {
        NodeId la_tail = regex_builder_get_lookahead_tail(self, node_id);
        NodeId la_body = nodeid_left(node_id, self);
        uint32_t rel = regex_builder_get_lookahead_rel(self, node_id);

        if (regex_builder_is_nullable(self, la_body, mask)) {
            NodeId right = nodeid_missing_to_eps(nodeid_right(node_id, self));
            return regex_builder_der(self, right, mask);
        }

        if (rel == UINT32_MAX) {
            TRegexId la_body_der = regex_builder_der(self, la_body, mask)!;
            if (nodeid_is_kind(la_tail, self, KIND_PRED)) {
                NodeId transitioned = regex_builder_transition_term(self, la_body_der,
                                                                     nodeid_pred_tset(la_tail, self));
                NodeId new_la = regex_builder_mk_lookahead_internal(self, transitioned, NODE_ID_MISSING, 0);
                NodeId concated = regex_builder_mk_concat(self, la_tail, new_la);
                return regex_builder_der(self, concated, mask);
            }
            if (nodeid_is_kind(la_tail, self, KIND_CONCAT)
                && nodeid_is_pred(nodeid_left(la_tail, self), self)) {
                NodeId left = nodeid_left(la_tail, self);
                TSetId tset = nodeid_pred_tset(left, self);
                NodeId transitioned = regex_builder_transition_term(self, la_body_der, tset);
                NodeId new_la = regex_builder_mk_lookahead_internal(self, transitioned, NODE_ID_MISSING, 0);
                NodeId tail_right = nodeid_right(la_tail, self);
                NodeId concated = regex_builder_mk_concat(self, new_la, tail_right);
                concated = regex_builder_mk_concat(self, left, concated);
                return regex_builder_der(self, concated, mask);
            }
        }

        if (!nodeid_eq(la_tail, NODE_ID_MISSING) && regex_builder_is_nullable(self, la_tail, mask)) {
            NodeId nulls_mask = regex_builder_extract_nulls_mask(self, la_tail, mask);
            NodeId concated = regex_builder_mk_concat(self, la_body, nulls_mask);
            NodeId concated_look = regex_builder_mk_lookahead_internal(self, concated, NODE_ID_MISSING, 0);
            NodeId non_nulled = regex_builder_mk_non_nullable_safe(self, la_tail);
            NodeId new_look = regex_builder_mk_lookahead_internal(self, la_body, non_nulled, rel);
            NodeId new_union = regex_builder_mk_union(self, concated_look, new_look);
            return regex_builder_der(self, new_union, mask);
        }

        TRegexId la_tail_der;
        if (nodeid_eq(la_tail, NODE_ID_MISSING)) {
            la_tail_der = TREGEX_ID_MISSING;
        }
        else if (regex_builder_is_nullable(self, la_tail, mask)) {
            NodeId nulls_mask = regex_builder_extract_nulls_mask(self, la_tail, mask);
            NodeId nulls_la = regex_builder_mk_lookahead_internal(self, nulls_mask, NODE_ID_MISSING, 0);
            NodeId la_union = regex_builder_mk_union(self, la_tail, nulls_la);
            la_tail_der = regex_builder_der(self, la_union, mask)!;
        }
        else {
            la_tail_der = regex_builder_der(self, la_tail, mask)!;
        }

        TRegexId la_body_der = regex_builder_der(self, la_body, mask)!;

        if (rel != UINT32_MAX && rel > self->lookahead_context_max) {
            return n00b_result_err(TRegexId, N00B_REGEX_ALGEBRA_ERR_ANCHOR_LIMIT);
        }

        TRegexId la;
        {
            LookaheadCtx ctx = (LookaheadCtx){ helpers_incr_rel(rel) };
            la = regex_builder_mk_binary(self, la_body_der, la_tail_der, mk_lookahead_thunk, &ctx);
        }

        if (rel != UINT32_MAX
            && !tregex_id_eq(la_tail_der, TREGEX_ID_MISSING)
            && regex_builder_is_nullable(self, la_tail, mask)) {
            TRegexId look_only;
            {
                LookaheadCtx ctx = (LookaheadCtx){ helpers_incr_rel(rel) };
                look_only = regex_builder_mk_binary(self, la_body_der, TREGEX_ID_MISSING,
                                                    mk_lookahead_thunk, &ctx);
            }
            result = regex_builder_mk_binary(self, look_only, la, mk_union_thunk, nullptr);
        }
        else {
            result = la;
        }
        break;
    }
    case KIND_COUNTED: {
        NodeId body  = nodeid_left(node_id, self);
        NodeId chain = nodeid_right(node_id, self);
        uint32_t packed = regex_builder_get_extra(self, node_id);
        uint16_t step = (uint16_t)(packed & 0xFFFFu);
        uint16_t best = (uint16_t)(packed >> 16);

        uint16_t mid_best = (regex_builder_is_nullable(self, body, mask) && step >= best) ? step : best;

        TRegexId body_der = regex_builder_der(self, body, mask)!;
        uint32_t s32 = (uint32_t)step + 1u;
        if (s32 > 0xFFFFu) s32 = 0xFFFFu;
        CountedCtx ctx = (CountedCtx){ chain, mask, mid_best, (uint16_t)s32 };
        result = regex_builder_mk_unary(self, body_der, mk_counted_thunk, &ctx);
        break;
    }
    case KIND_BEGIN: case KIND_END:
        result = TREGEX_ID_BOT;
        break;
    case KIND_PRED: {
        TSetId psi = nodeid_pred_tset(node_id, self);
        if (psi.v == TSET_ID_EMPTY.v) {
            result = TREGEX_ID_BOT;
        }
        else {
            result = regex_builder_mk_ite(self, psi, TREGEX_ID_EPS, TREGEX_ID_BOT);
        }
        break;
    }
    }
    /* If a mk_binary / mk_unary / mk_ite call exceeded the algebra state
     * cap, the latch on `self` is sticky.  Surface the error here rather
     * than caching a poisoned `result` and continuing to expand state. */
    if (self->state_space_err) {
        return n00b_result_err(TRegexId, N00B_REGEX_ALGEBRA_ERR_STATE_SPACE_EXPLOSION);
    }
    regex_builder_cache_der(self, node_id, result, mask);
    return n00b_result_ok(TRegexId, result);
}

// ============================================================================
// init_metadata / cache_reversed.
// ============================================================================

static void
regex_builder_init_metadata(RegexBuilder *self, NodeId node_id, MetadataId meta_id)
{
    while (self->metadata.len <= node_id.v) {
        VecMetadataId_push(&self->metadata, METADATA_ID_MISSING, self->allocator);
    }
    self->metadata.data[node_id.v] = meta_id;
}

static NodeId
regex_builder_cache_reversed(RegexBuilder *self, NodeId node_id, NodeId reversed_id)
{
    while (self->reversed.len <= node_id.v) {
        VecNodeId_push(&self->reversed, NODE_ID_MISSING, self->allocator);
    }
    self->reversed.data[node_id.v] = reversed_id;
    return reversed_id;
}

// ============================================================================
// regex_builder_init (the big per-Kind metadata initialiser + post-init
// simplifier).  Mirrors Rust `RegexBuilder::init` exactly.
// ============================================================================

NodeId regex_builder_override_as(RegexBuilder *self, NodeId key, NodeId subsumed);

static NodeId
regex_builder_init(RegexBuilder *self, NodeKey inst)
{
    self->num_created += 1;
    NodeId node_id = (NodeId){ self->num_created };
    node_key_map_insert(self->index, inst, node_id);

    switch (inst.kind) {
    case KIND_PRED: {
        MetadataId meta_id = metadata_builder_get_meta_id(&self->mb,
            (Metadata){ .flags = METAFLAGS_ZERO, .nulls = NULLS_ID_EMPTY });
        regex_builder_init_metadata(self, node_id, meta_id);
        break;
    }
    case KIND_BEGIN: {
        MetadataId meta_id = metadata_builder_get_meta_id(&self->mb, (Metadata){
            .flags = metaflags_with_nullability(NULLABILITY_BEGIN, METAFLAGS_CONTAINS_ANCHORS),
            .nulls = NULLS_ID_BEGIN0,
        });
        regex_builder_init_metadata(self, node_id, meta_id);
        break;
    }
    case KIND_END: {
        MetadataId meta_id = metadata_builder_get_meta_id(&self->mb, (Metadata){
            .flags = metaflags_with_nullability(NULLABILITY_END, METAFLAGS_CONTAINS_ANCHORS),
            .nulls = NULLS_ID_END0,
        });
        regex_builder_init_metadata(self, node_id, meta_id);
        break;
    }
    case KIND_INTER: {
        MetadataId m1 = regex_builder_get_node_meta_id(self, inst.left);
        MetadataId m2 = regex_builder_get_node_meta_id(self, inst.right);
        NullsId left_nulls  = metadata_builder_get_meta_ref(&self->mb, m1)->nulls;
        Nullability mask_l  = nodeid_nullability(inst.left, self);
        Nullability mask_r  = nodeid_nullability(inst.right, self);
        NullsId right_nulls = metadata_builder_get_meta_ref(&self->mb, m2)->nulls;
        NullsId nulls = nulls_builder_and_id(&self->mb.nb, left_nulls, right_nulls);
        nulls = nulls_builder_and_mask(&self->mb.nb, nulls, mask_l);
        nulls = nulls_builder_and_mask(&self->mb.nb, nulls, mask_r);
        Metadata new_meta = (Metadata){
            .flags = metadata_builder_flags_inter(&self->mb, m1, m2),
            .nulls = nulls,
        };
        MetadataId meta_id = metadata_builder_get_meta_id(&self->mb, new_meta);
        regex_builder_init_metadata(self, node_id, meta_id);
        break;
    }
    case KIND_UNION: {
        MetadataId m1 = regex_builder_get_node_meta_id(self, inst.left);
        MetadataId m2 = regex_builder_get_node_meta_id(self, inst.right);
        NullsId left_nulls  = metadata_builder_get_meta_ref(&self->mb, m1)->nulls;
        NullsId right_nulls = metadata_builder_get_meta_ref(&self->mb, m2)->nulls;
        NullsId nulls = nulls_builder_or_id(&self->mb.nb, left_nulls, right_nulls);
        Metadata new_meta = (Metadata){
            .flags = metadata_builder_flags_union(&self->mb, m1, m2),
            .nulls = nulls,
        };
        MetadataId meta_id = metadata_builder_get_meta_id(&self->mb, new_meta);
        regex_builder_init_metadata(self, node_id, meta_id);
        break;
    }
    case KIND_CONCAT: {
        MetaFlags flags = metadata_builder_flags_concat(&self->mb,
            regex_builder_get_node_meta_id(self, inst.left),
            regex_builder_get_node_meta_id(self, inst.right));
        Nullability right_nullability = nodeid_nullability(inst.right, self);
        Nullability left_nullability  = nodeid_nullability(inst.left,  self);
        NullsId nulls_left  = regex_builder_get_nulls_id(self, inst.left);
        NullsId nulls_right = regex_builder_get_nulls_id(self, inst.right);
        NullsId nulls = nulls_builder_or_id(&self->mb.nb, nulls_left, nulls_right);
        Nullability mask = nullability_and(right_nullability, left_nullability);
        nulls = nulls_builder_and_mask(&self->mb.nb, nulls, mask);
        MetadataId new_id = metadata_builder_get_meta_id(&self->mb,
            (Metadata){ .flags = flags, .nulls = nulls });
        regex_builder_init_metadata(self, node_id, new_id);
        break;
    }
    case KIND_STAR: {
        NullsId left_nulls = regex_builder_get_nulls_id(self, inst.left);
        NullsId nulls = nulls_builder_or_id(&self->mb.nb, left_nulls, NULLS_ID_ALWAYS0);
        MetadataId meta_id = metadata_builder_get_meta_id(&self->mb, (Metadata){
            .flags = metadata_builder_flags_star(&self->mb,
                regex_builder_get_node_meta_id(self, inst.left), inst.left),
            .nulls = nulls,
        });
        regex_builder_init_metadata(self, node_id, meta_id);
        break;
    }
    case KIND_COMPL: {
        NullsId nulls = nulls_builder_not_id(&self->mb.nb, regex_builder_get_nulls_id(self, inst.left));
        MetadataId meta_id = metadata_builder_get_meta_id(&self->mb, (Metadata){
            .flags = metadata_builder_flags_compl(&self->mb,
                regex_builder_get_node_meta_id(self, inst.left)),
            .nulls = nulls,
        });
        regex_builder_init_metadata(self, node_id, meta_id);
        break;
    }
    case KIND_LOOKBEHIND: {
        Nullability left_nullability = regex_builder_nullability(self, inst.left);
        MetaFlags contains_flags = regex_builder_get_flags_contains(self, inst.left);
        NullsId nulls;
        if (nodeid_is_missing(inst.right)) {
            nulls = regex_builder_get_nulls_id(self, inst.left);
        }
        else {
            Nullability right_nullability = regex_builder_nullability(self, inst.right);
            NullsId nulls_left  = regex_builder_get_nulls_id_w_mask(self, inst.right, right_nullability);
            NullsId nulls_right = regex_builder_get_nulls_id_w_mask(self, inst.right, left_nullability);
            left_nullability = nullability_and(left_nullability, right_nullability);
            contains_flags = metaflags_or(contains_flags, regex_builder_get_flags_contains(self, inst.right));
            nulls = nulls_builder_and_id(&self->mb.nb, nulls_left, nulls_right);
        }
        MetadataId meta_id = metadata_builder_get_meta_id(&self->mb, (Metadata){
            .flags = metaflags_with_nullability(left_nullability,
                metaflags_or(contains_flags, METAFLAGS_CONTAINS_LOOKBEHIND)),
            .nulls = nulls,
        });
        regex_builder_init_metadata(self, node_id, meta_id);
        break;
    }
    case KIND_LOOKAHEAD: {
        NullsId nulls = regex_builder_get_nulls_id(self, inst.left);
        nulls = nulls_builder_add_rel(&self->mb.nb, nulls, inst.extra);
        Nullability left_nullability = nodeid_nullability(inst.left, self);
        NullsId nulls_right = regex_builder_get_nulls_id_w_mask(self, inst.right, left_nullability);
        nulls = nulls_builder_or_id(&self->mb.nb, nulls, nulls_right);

        NodeId la_inner = inst.left;
        NodeId la_tail  = inst.right;
        Nullability null_v = nullability_and(
            metaflags_nullability(regex_builder_get_meta_flags(self, la_inner)),
            metaflags_nullability(regex_builder_get_meta_flags(self, nodeid_missing_to_eps(la_tail))));
        MetaFlags contains_flags = metaflags_or(
            regex_builder_get_flags_contains(self, la_inner),
            regex_builder_get_flags_contains(self, la_tail));

        MetadataId meta_id = metadata_builder_get_meta_id(&self->mb, (Metadata){
            .flags = metaflags_with_nullability(null_v,
                metaflags_or(contains_flags, METAFLAGS_CONTAINS_LOOKAHEAD)),
            .nulls = nulls,
        });
        regex_builder_init_metadata(self, node_id, meta_id);
        break;
    }
    case KIND_COUNTED: {
        uint32_t best = inst.extra >> 16;
        Nullability null_v;
        NullsId nulls;
        if (best > 0) {
            null_v = NULLABILITY_CENTER;
            nulls  = nulls_builder_get_id_singleton(&self->mb.nb,
                        null_state_new(NULLABILITY_CENTER, best));
        }
        else {
            null_v = NULLABILITY_NEVER;
            nulls  = NULLS_ID_EMPTY;
        }
        MetadataId meta_id = metadata_builder_get_meta_id(&self->mb, (Metadata){
            .flags = metaflags_with_nullability(null_v, METAFLAGS_ZERO),
            .nulls = nulls,
        });
        regex_builder_init_metadata(self, node_id, meta_id);
        break;
    }
    }

    VecNodeKey_push(&self->array, inst, self->allocator);

    NodeId rw = regex_builder_post_init_simplify(self, node_id);
    if (rw.v != NODE_ID_MISSING.v) {
        return regex_builder_override_as(self, node_id, rw);
    }
    return node_id;
}

// ============================================================================
// post_init_simplify and helpers.
// ============================================================================

typedef struct {
    NodeId lhs;
    bool   subsumed;
} UnionVisitorCtx;

static bool
union_visitor_check_subsumed(void *ctx_v, RegexBuilder *b, NodeId branch)
{
    UnionVisitorCtx *ctx = ctx_v;
    if (regex_builder_nullable_subsumes(b, branch, ctx->lhs)) {
        ctx->subsumed = true;
    }
    return !ctx->subsumed;
}

static NodeId
regex_builder_post_init_simplify(RegexBuilder *self, NodeId node_id)
{
    Kind k = regex_builder_get_kind(self, node_id);
    switch (k) {
    case KIND_CONCAT: {
        NodeId lhs = nodeid_left(node_id, self);
        NodeId rhs = nodeid_right(node_id, self);
        NodeId _pred_star_inner;
        if (nodeid_is_pred_star(lhs, self, &_pred_star_inner)) {
            NodeId opttail;
            if (nodeid_is_opt_v(rhs, self, &opttail)) {
                bool known;
                bool sub = regex_builder_subsumes(self, lhs, opttail, &known);
                if (known && sub) return lhs;
            }
        }
        break;
    }
    case KIND_UNION: {
        NodeId lhs = nodeid_left(node_id, self);
        NodeId rhs = nodeid_right(node_id, self);
        UnionVisitorCtx ctx = (UnionVisitorCtx){ lhs, false };
        regex_builder_iter_union_while(self, rhs, &ctx, union_visitor_check_subsumed);
        if (ctx.subsumed) return rhs;
        if (lhs.v != rhs.v && regex_builder_union_branches_subset(self, lhs, rhs)) return rhs;
        break;
    }
    default: break;
    }
    return NODE_ID_MISSING;
}

static bool
regex_builder_subsumes(RegexBuilder *self, NodeId a, NodeId b, bool *out_known)
{
    bool subsumes = false;
    *out_known = false;
    (void)regex_builder_subsumes_known(self, a, b, out_known, &subsumes);
    return subsumes;
}

static bool
regex_builder_union_branches_subset(RegexBuilder *self, NodeId lhs, NodeId rhs)
{
    if (regex_builder_get_kind(self, lhs) != KIND_UNION) return false;
    typedef struct { NodeId *data; size_t len; size_t cap; } VecNI;
    VecNI rhs_branches = (VecNI){};
    NodeId curr = rhs;
    while (regex_builder_get_kind(self, curr) == KIND_UNION) {
        if (rhs_branches.len == rhs_branches.cap) {
            size_t nc = rhs_branches.cap ? safe_mul_sz(rhs_branches.cap, 2) : 8;
            grow_buf(NodeId, self->allocator, &rhs_branches.data, &rhs_branches.cap, rhs_branches.len, nc);
        }
        rhs_branches.data[rhs_branches.len++] = regex_builder_get_left(self, curr);
        curr = regex_builder_get_right(self, curr);
    }
    if (rhs_branches.len == rhs_branches.cap) {
        size_t nc = rhs_branches.cap ? safe_mul_sz(rhs_branches.cap, 2) : 8;
        grow_buf(NodeId, self->allocator, &rhs_branches.data, &rhs_branches.cap, rhs_branches.len, nc);
    }
    rhs_branches.data[rhs_branches.len++] = curr;

    bool ok = true;
    curr = lhs;
    while (regex_builder_get_kind(self, curr) == KIND_UNION) {
        NodeId leftc = regex_builder_get_left(self, curr);
        bool found = false;
        for (size_t i = 0; i < rhs_branches.len; i++) {
            if (rhs_branches.data[i].v == leftc.v) { found = true; break; }
        }
        if (!found) { ok = false; goto done; }
        curr = regex_builder_get_right(self, curr);
    }
    {
        bool found = false;
        for (size_t i = 0; i < rhs_branches.len; i++) {
            if (rhs_branches.data[i].v == curr.v) { found = true; break; }
        }
        ok = found;
    }
done:
    if (rhs_branches.data) n00b_free(rhs_branches.data);
    return ok;
}

static bool
regex_builder_nullable_subsumes(RegexBuilder *self, NodeId node, NodeId target)
{
    if (node.v == target.v) return true;
    Kind k = regex_builder_get_kind(self, node);
    if (k == KIND_UNION) {
        return regex_builder_nullable_subsumes(self, regex_builder_get_left(self, node), target)
            || regex_builder_nullable_subsumes(self, regex_builder_get_right(self, node), target);
    }
    if (k == KIND_CONCAT && regex_builder_is_always_nullable(self, regex_builder_get_left(self, node))) {
        return regex_builder_nullable_subsumes(self, regex_builder_get_right(self, node), target);
    }
    return false;
}

// ============================================================================
// Public top-level helpers (num_nodes, tree_size, get_node_id, init_as,
// override_as).
// ============================================================================

uint32_t
regex_builder_num_nodes(const RegexBuilder *self)
{
    n00b_require(self != nullptr, "regex_builder_num_nodes: self must not be null");
    return self->num_created;
}

size_t
regex_builder_tree_size(const RegexBuilder *self, NodeId root, size_t limit)
{
    n00b_require(self != nullptr, "regex_builder_tree_size: self must not be null");
    n00b_require((size_t)root.v < self->array.len,
                 "regex_builder_tree_size: root NodeId out of bounds");
    NodeIdHashSet *seen = NodeIdHashSet_new(self->allocator);
    typedef struct { NodeId *data; size_t len; size_t cap; } Stack;
    Stack stack = (Stack){};
    size_t init_cap = 16;
    stack.cap = init_cap;
    stack.data = n00b_alloc_array_with_opts(NodeId, init_cap,
        &(n00b_alloc_opts_t){
            .allocator = self->allocator,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    stack.data[stack.len++] = root;

    size_t result = 0;
    while (stack.len > 0) {
        NodeId n = stack.data[--stack.len];
        if (n.v == NODE_ID_MISSING.v || n.v == NODE_ID_BOT.v || n.v == NODE_ID_EPS.v
            || n.v == NODE_ID_TS.v || n.v == NODE_ID_BEGIN.v || n.v == NODE_ID_END.v) {
            continue;
        }
        if (!NodeIdHashSet_insert(seen, n)) continue;
        if (NodeIdHashSet_len(seen) >= limit) { result = limit; goto done; }
        if (stack.len + 2 > stack.cap) {
            size_t nc = safe_mul_sz(stack.cap, 2);
            grow_buf(NodeId, self->allocator, &stack.data, &stack.cap, stack.len, nc);
        }
        stack.data[stack.len++] = regex_builder_get_left(self, n);
        stack.data[stack.len++] = regex_builder_get_right(self, n);
    }
    result = NodeIdHashSet_len(seen);
done:
    if (stack.data) n00b_free(stack.data);
    return result;
}

static NodeId
regex_builder_get_node_id(RegexBuilder *self, NodeKey inst)
{
    NodeId existing;
    if (node_key_map_get(self->index, inst, &existing)) return existing;
    return regex_builder_init(self, inst);
}

static NodeId
regex_builder_init_as(RegexBuilder *self, NodeKey key, NodeId subsumed)
{
    node_key_map_insert(self->index, key, subsumed);
    return subsumed;
}

NodeId
regex_builder_override_as(RegexBuilder *self, NodeId key, NodeId subsumed)
{
    NodeKey *kp = &self->array.data[key.v];
    node_key_map_insert(self->index, *kp, subsumed);
    return subsumed;
}

// ----------------------------------------------------------------------------
// concat-tree walk helpers used by has_trailing_la / strip_trailing_la.
// ----------------------------------------------------------------------------

static NodeId
regex_builder_get_concat_end(RegexBuilder *self, NodeId node_id)
{
    NodeId curr = node_id;
    while (regex_builder_get_kind(self, curr) == KIND_CONCAT) {
        curr = nodeid_right(curr, self);
    }
    return curr;
}

static bool
regex_builder_has_trailing_la(RegexBuilder *self, NodeId node)
{
    NodeId end;
    Kind k = regex_builder_get_kind(self, node);
    if (k == KIND_CONCAT) {
        end = regex_builder_get_concat_end(self, node);
    }
    else if (k == KIND_LOOKAHEAD) {
        end = node;
    }
    else {
        return false;
    }
    return regex_builder_get_kind(self, end) == KIND_LOOKAHEAD
        && nodeid_is_missing(nodeid_right(end, self));
}

typedef struct { NodeId stripped; NodeId la; } StripPair;

static StripPair
regex_builder_strip_trailing_la(RegexBuilder *self, NodeId node)
{
    if (regex_builder_get_kind(self, node) == KIND_LOOKAHEAD) {
        return (StripPair){ NODE_ID_EPS, node };
    }
    NodeId right = nodeid_right(node, self);
    if (regex_builder_get_kind(self, right) != KIND_CONCAT) {
        return (StripPair){ nodeid_left(node, self), right };
    }
    StripPair sp = regex_builder_strip_trailing_la(self, right);
    return (StripPair){
        regex_builder_mk_concat(self, nodeid_left(node, self), sp.stripped),
        sp.la,
    };
}

// ============================================================================
// strip_lb / nonbegins / strip_prefix_safe / prune_begin / prune_begin_eps /
// normalize_rev.
// ============================================================================

static n00b_regex_algebra_err_t regex_builder_strip_lb_inner(RegexBuilder *self, NodeId node_id, NodeId *out);

n00b_result_t(NodeId)
regex_builder_strip_lb(RegexBuilder *self, NodeId node_id)
{
    n00b_require(self != nullptr, "regex_builder_strip_lb: self must not be null");
    n00b_require((size_t)node_id.v < self->array.len, "regex_builder_strip_lb: NodeId out of bounds");
    if (nodeid_is_concat(node_id, self)
        && nodeid_eq(nodeid_left(node_id, self), NODE_ID_BEGIN)) {
        return regex_builder_strip_lb(self, nodeid_right(node_id, self));
    }
    NodeId out;
    n00b_regex_algebra_err_t e = regex_builder_strip_lb_inner(self, node_id, &out);
    if (e != N00B_REGEX_ALGEBRA_ERR_NONE) {
        return n00b_result_err(NodeId, e);
    }
    return n00b_result_ok(NodeId, out);
}

static n00b_regex_algebra_err_t
regex_builder_strip_lb_inner(RegexBuilder *self, NodeId node_id, NodeId *out)
{
    if (!regex_builder_contains_look(self, node_id)) {
        *out = node_id;
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    if (nodeid_is_concat(node_id, self)
        && nodeid_is_lookbehind(nodeid_left(node_id, self), self)) {
        NodeId lb = nodeid_left(node_id, self);
        NodeId prev = regex_builder_get_lookbehind_prev(self, lb);
        NodeId tail;
        n00b_regex_algebra_err_t e = regex_builder_strip_lb_inner(self, nodeid_right(node_id, self), &tail);
        if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
        if (!nodeid_eq(prev, NODE_ID_MISSING)) {
            NodeId stripped_prev;
            e = regex_builder_strip_lb_inner(self, prev, &stripped_prev);
            if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
            *out = regex_builder_mk_concat(self, stripped_prev, tail);
            return N00B_REGEX_ALGEBRA_ERR_NONE;
        }
        *out = tail;
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    if (nodeid_is_inter(node_id, self)) {
        NodeId left, right;
        n00b_regex_algebra_err_t e = regex_builder_strip_lb_inner(self, nodeid_left(node_id, self), &left);
        if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
        e = regex_builder_strip_lb_inner(self, nodeid_right(node_id, self), &right);
        if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
        *out = regex_builder_mk_inter(self, left, right);
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    if (regex_builder_get_kind(self, node_id) == KIND_UNION) {
        NodeId left, right;
        n00b_regex_algebra_err_t e = regex_builder_strip_lb_inner(self, nodeid_left(node_id, self), &left);
        if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
        e = regex_builder_strip_lb_inner(self, nodeid_right(node_id, self), &right);
        if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return e;
        *out = regex_builder_mk_union(self, left, right);
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    switch (regex_builder_get_kind(self, node_id)) {
    case KIND_LOOKBEHIND: {
        NodeId prev = regex_builder_get_lookbehind_prev(self, node_id);
        if (!nodeid_eq(prev, NODE_ID_MISSING)) {
            return regex_builder_strip_lb_inner(self, prev, out);
        }
        *out = NODE_ID_EPS;
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    case KIND_LOOKAHEAD:
        if (nodeid_is_missing(regex_builder_get_lookahead_tail(self, node_id))) {
            return N00B_REGEX_ALGEBRA_ERR_UNSUPPORTED_PATTERN;
        }
        *out = node_id;
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    default:
        *out = node_id;
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
}

NodeId
regex_builder_nonbegins(RegexBuilder *self, NodeId node_id)
{
    n00b_require(self != nullptr, "regex_builder_nonbegins: self must not be null");
    n00b_require((size_t)node_id.v < self->array.len, "regex_builder_nonbegins: NodeId out of bounds");
    if (!regex_builder_contains_anchors(self, node_id)) return node_id;
    switch (regex_builder_get_kind(self, node_id)) {
    case KIND_BEGIN:
        return NODE_ID_BOT;
    case KIND_CONCAT: {
        NodeId left = regex_builder_nonbegins(self, nodeid_left(node_id, self));
        if (nodeid_eq(left, NODE_ID_BOT)) return NODE_ID_BOT;
        return regex_builder_mk_concat(self, left, nodeid_right(node_id, self));
    }
    case KIND_UNION: {
        NodeId left  = regex_builder_nonbegins(self, nodeid_left(node_id, self));
        NodeId right = regex_builder_nonbegins(self, nodeid_right(node_id, self));
        return regex_builder_mk_union(self, left, right);
    }
    default:
        return node_id;
    }
}

NodeId
regex_builder_strip_prefix_safe(RegexBuilder *self, NodeId node_id)
{
    n00b_require(self != nullptr, "regex_builder_strip_prefix_safe: self must not be null");
    n00b_require((size_t)node_id.v < self->array.len, "regex_builder_strip_prefix_safe: NodeId out of bounds");
    if (regex_builder_get_kind(self, node_id) == KIND_CONCAT) {
        NodeId head = nodeid_left(node_id, self);
        if (regex_builder_any_nonbegin_nullable(self, head)) {
            return regex_builder_strip_prefix_safe(self, nodeid_right(node_id, self));
        }
    }
    return node_id;
}

NodeId
regex_builder_prune_begin(RegexBuilder *self, NodeId node_id)
{
    n00b_require(self != nullptr, "regex_builder_prune_begin: self must not be null");
    n00b_require((size_t)node_id.v < self->array.len, "regex_builder_prune_begin: NodeId out of bounds");
    switch (regex_builder_get_kind(self, node_id)) {
    case KIND_BEGIN:
        return NODE_ID_BOT;
    case KIND_CONCAT: {
        NodeId head = regex_builder_prune_begin(self, nodeid_left(node_id, self));
        NodeId tail = regex_builder_prune_begin(self, nodeid_right(node_id, self));
        return regex_builder_mk_concat(self, head, tail);
    }
    case KIND_LOOKBEHIND: {
        if (!nodeid_is_missing(nodeid_right(node_id, self))) return node_id;
        return regex_builder_prune_begin(self, nodeid_left(node_id, self));
    }
    case KIND_UNION: {
        NodeId left  = regex_builder_prune_begin(self, nodeid_left(node_id, self));
        NodeId right = regex_builder_prune_begin(self, nodeid_right(node_id, self));
        return regex_builder_mk_union(self, left, right);
    }
    default:
        return node_id;
    }
}

NodeId
regex_builder_prune_begin_eps(RegexBuilder *self, NodeId node_id)
{
    n00b_require(self != nullptr, "regex_builder_prune_begin_eps: self must not be null");
    n00b_require((size_t)node_id.v < self->array.len, "regex_builder_prune_begin_eps: NodeId out of bounds");
    switch (regex_builder_get_kind(self, node_id)) {
    case KIND_BEGIN:
        return NODE_ID_EPS;
    case KIND_CONCAT: {
        NodeId head = regex_builder_prune_begin_eps(self, nodeid_left(node_id, self));
        NodeId tail = regex_builder_prune_begin_eps(self, nodeid_right(node_id, self));
        return regex_builder_mk_concat(self, head, tail);
    }
    case KIND_LOOKBEHIND: {
        if (!nodeid_is_missing(nodeid_right(node_id, self))) return node_id;
        return regex_builder_prune_begin_eps(self, nodeid_left(node_id, self));
    }
    case KIND_UNION: {
        NodeId left  = regex_builder_prune_begin_eps(self, nodeid_left(node_id, self));
        NodeId right = regex_builder_prune_begin_eps(self, nodeid_right(node_id, self));
        return regex_builder_mk_union(self, left, right);
    }
    default:
        return node_id;
    }
}

n00b_result_t(NodeId)
regex_builder_normalize_rev(RegexBuilder *self, NodeId node_id)
{
    n00b_require(self != nullptr, "regex_builder_normalize_rev: self must not be null");
    n00b_require((size_t)node_id.v < self->array.len, "regex_builder_normalize_rev: NodeId out of bounds");
    if (!regex_builder_contains_look(self, node_id)
        && !regex_builder_contains_anchors(self, node_id)) {
        return n00b_result_ok(NodeId, node_id);
    }
    NodeId result;
    switch (regex_builder_get_kind(self, node_id)) {
    case KIND_CONCAT: {
        NodeId left  = regex_builder_normalize_rev(self, nodeid_left(node_id, self))!;
        NodeId right = regex_builder_normalize_rev(self, nodeid_right(node_id, self))!;
        result = regex_builder_mk_concat(self, left, right);
        break;
    }
    case KIND_INTER: {
        NodeId left  = regex_builder_normalize_rev(self, nodeid_left(node_id, self))!;
        NodeId right = regex_builder_normalize_rev(self, nodeid_right(node_id, self))!;
        result = regex_builder_mk_inter(self, left, right);
        break;
    }
    case KIND_UNION: {
        NodeId left  = regex_builder_normalize_rev(self, nodeid_left(node_id, self))!;
        NodeId right = regex_builder_normalize_rev(self, nodeid_right(node_id, self))!;
        result = regex_builder_mk_union(self, left, right);
        break;
    }
    case KIND_LOOKBEHIND: {
        NodeId left  = regex_builder_normalize_rev(self, nodeid_left(node_id, self))!;
        NodeId right = regex_builder_normalize_rev(self, nodeid_missing_to_eps(nodeid_right(node_id, self)))!;
        NodeId lbody_ts = regex_builder_mk_concat(self, NODE_ID_TS, left);
        NodeId ltail_ts = regex_builder_mk_concat(self, NODE_ID_TS, right);
        result = regex_builder_mk_inter(self, lbody_ts, ltail_ts);
        break;
    }
    case KIND_LOOKAHEAD:
        if (!nodeid_is_missing(regex_builder_get_lookahead_tail(self, node_id))) {
            return n00b_result_err(NodeId, N00B_REGEX_ALGEBRA_ERR_UNSUPPORTED_PATTERN);
        }
        result = node_id;
        break;
    default:
        result = node_id;
        break;
    }
    return n00b_result_ok(NodeId, result);
}

// ============================================================================
// collect_der_targets / ts_rev_start / reverse.
// ============================================================================

void
regex_builder_collect_der_targets(RegexBuilder *self, TRegexId der, TSetId path_set,
                                  VecDerTarget *out)
{
    const TRegex_TSetId *t = regex_builder_get_tregex(self, der);
    switch (t->selector) {
    case typehash(TRegex_leaf_t): {
        NodeId target = n00b_variant_get(*t, TRegex_leaf_t).leaf;
        for (size_t i = 0; i < out->len; i++) {
            if (out->data[i].target.v == target.v) {
                out->data[i].path = solver_or_id(regex_builder_solver(self),
                                                 out->data[i].path, path_set);
                return;
            }
        }
        if (out->len == out->cap) {
            size_t nc = out->cap ? safe_mul_sz(out->cap, 2) : 8;
            grow_buf(DerTarget, self->allocator, &out->data, &out->cap, out->len, nc);
        }
        out->data[out->len++] = (DerTarget){ target, path_set };
        break;
    }
    case typehash(TRegex_ite_t): {
        TRegex_ite_t _i   = n00b_variant_get(*t, TRegex_ite_t);
        TSetId   cond     = _i.set;
        TRegexId then_b   = _i.then_id;
        TRegexId else_b   = _i.else_id;
        TSetId   then_path = solver_and_id(regex_builder_solver(self), path_set, cond);
        regex_builder_collect_der_targets(self, then_b, then_path, out);
        TSetId   not_cond  = solver_not_id(regex_builder_solver(self), cond);
        TSetId   else_path = solver_and_id(regex_builder_solver(self), path_set, not_cond);
        regex_builder_collect_der_targets(self, else_b, else_path, out);
        break;
    }
    }
}

extern NodeId regex_builder_simplify_rev_initial(RegexBuilder *self, NodeId n);
extern NodeId regex_builder_mk_star(RegexBuilder *self, NodeId body);
extern NodeId regex_builder_mk_lookbehind(RegexBuilder *self, NodeId body, NodeId prev);
extern NodeId regex_builder_mk_lookahead(RegexBuilder *self, NodeId body, NodeId tail, uint32_t rel);

n00b_result_t(NodeId)
regex_builder_ts_rev_start(RegexBuilder *self, NodeId node_id)
{
    n00b_require(self != nullptr, "regex_builder_ts_rev_start: self must not be null");
    n00b_require((size_t)node_id.v < self->array.len, "regex_builder_ts_rev_start: NodeId out of bounds");
    NodeId rev = regex_builder_reverse(self, node_id)!;
    rev = regex_builder_normalize_rev(self, rev)!;
    NodeId with_ts;
    if (nodeid_is_concat(rev, self) && nodeid_eq(nodeid_left(rev, self), NODE_ID_BEGIN)) {
        with_ts = rev;
    }
    else {
        with_ts = regex_builder_mk_concat(self, NODE_ID_TS, rev);
    }
    return n00b_result_ok(NodeId, regex_builder_simplify_rev_initial(self, with_ts));
}

n00b_result_t(NodeId)
regex_builder_reverse(RegexBuilder *self, NodeId node_id)
{
    if (self->reversed.len > node_id.v) {
        NodeId cached = self->reversed.data[node_id.v];
        if (!nodeid_eq(cached, NODE_ID_MISSING)) {
            return n00b_result_ok(NodeId, cached);
        }
    }
    NodeId rw;
    switch (regex_builder_get_kind(self, node_id)) {
    case KIND_END:   rw = NODE_ID_BEGIN; break;
    case KIND_BEGIN: rw = NODE_ID_END;   break;
    case KIND_PRED:  rw = node_id;       break;
    case KIND_CONCAT: {
        NodeId left  = regex_builder_reverse(self, nodeid_left(node_id, self))!;
        NodeId right = regex_builder_reverse(self, nodeid_right(node_id, self))!;
        rw = regex_builder_mk_concat(self, right, left);
        break;
    }
    case KIND_UNION: {
        NodeId left  = regex_builder_reverse(self, nodeid_left(node_id, self))!;
        NodeId right = regex_builder_reverse(self, nodeid_right(node_id, self))!;
        rw = regex_builder_mk_union(self, left, right);
        break;
    }
    case KIND_INTER: {
        NodeId left  = regex_builder_reverse(self, nodeid_left(node_id, self))!;
        NodeId right = regex_builder_reverse(self, nodeid_right(node_id, self))!;
        rw = regex_builder_mk_inter(self, left, right);
        break;
    }
    case KIND_STAR: {
        NodeId body = regex_builder_reverse(self, nodeid_left(node_id, self))!;
        rw = regex_builder_mk_star(self, body);
        break;
    }
    case KIND_COMPL: {
        if (regex_builder_contains_look(self, nodeid_left(node_id, self))) {
            return n00b_result_err(NodeId, N00B_REGEX_ALGEBRA_ERR_UNSUPPORTED_PATTERN);
        }
        NodeId body = regex_builder_reverse(self, nodeid_left(node_id, self))!;
        rw = regex_builder_mk_compl(self, body);
        break;
    }
    case KIND_LOOKBEHIND: {
        NodeId prev = regex_builder_get_lookbehind_prev(self, node_id);
        NodeId inner_id = regex_builder_get_lookbehind_inner(self, node_id);
        NodeId rev_inner = regex_builder_reverse(self, inner_id)!;
        NodeId rev_prev;
        if (!nodeid_eq(prev, NODE_ID_MISSING)) {
            rev_prev = regex_builder_reverse(self, prev)!;
        }
        else {
            rev_prev = NODE_ID_MISSING;
        }
        rw = regex_builder_mk_lookahead(self, rev_inner, rev_prev, 0);
        break;
    }
    case KIND_LOOKAHEAD: {
        uint32_t rel = regex_builder_get_lookahead_rel(self, node_id);
        if (rel == UINT32_MAX) {
            NodeId lbody = regex_builder_get_lookahead_inner(self, node_id);
            NodeId ltail = nodeid_missing_to_eps(regex_builder_get_lookahead_tail(self, node_id));
            NodeId rbody = regex_builder_reverse(self, lbody)!;
            NodeId rtail = regex_builder_reverse(self, ltail)!;
            NodeId rev = regex_builder_mk_lookbehind(self, rbody, rtail);
            return n00b_result_ok(NodeId, regex_builder_cache_reversed(self, node_id, rev));
        }
        if (rel != 0) return n00b_result_err(NodeId, N00B_REGEX_ALGEBRA_ERR_UNSUPPORTED_PATTERN);
        NodeId tail_node = regex_builder_get_lookahead_tail(self, node_id);
        NodeId rev_tail;
        if (!nodeid_eq(tail_node, NODE_ID_MISSING)) {
            rev_tail = regex_builder_reverse(self, tail_node)!;
        }
        else {
            rev_tail = NODE_ID_MISSING;
        }
        NodeId inner_id = regex_builder_get_lookahead_inner(self, node_id);
        NodeId rev_inner = regex_builder_reverse(self, inner_id)!;
        rw = regex_builder_mk_lookbehind(self, rev_inner, rev_tail);
        break;
    }
    case KIND_COUNTED:
        return n00b_result_err(NodeId, N00B_REGEX_ALGEBRA_ERR_UNSUPPORTED_PATTERN);
    default:
        rw = node_id;
        break;
    }
    regex_builder_cache_reversed(self, node_id, rw);
    return n00b_result_ok(NodeId, rw);
}

// ============================================================================
// mk_pred / mk_compl / extract_nulls_mask.
// ============================================================================

NodeId
regex_builder_mk_pred(RegexBuilder *self, TSetId pred)
{
    n00b_require(self != nullptr, "regex_builder_mk_pred: self must not be null");
    NodeKey node = (NodeKey){
        .kind  = KIND_PRED,
        .left  = NODE_ID_MISSING,
        .right = NODE_ID_MISSING,
        .extra = pred.v,
    };
    return regex_builder_get_node_id(self, node);
}

NodeId
regex_builder_mk_compl(RegexBuilder *self, NodeId body)
{
    n00b_require(self != nullptr, "regex_builder_mk_compl: self must not be null");
    n00b_require((size_t)body.v < self->array.len, "regex_builder_mk_compl: NodeId out of bounds");
    NodeKey key = (NodeKey){
        .kind  = KIND_COMPL,
        .left  = body,
        .right = NODE_ID_MISSING,
        .extra = UINT32_MAX,
    };
    NodeId existing;
    if (node_key_map_get(self->index, key, &existing)) return existing;
    if (nodeid_eq(body, NODE_ID_BOT)) return NODE_ID_TS;
    if (nodeid_eq(body, NODE_ID_TS))  return NODE_ID_BOT;

    NodeId contains_body;
    if (nodeid_is_contains(body, self, &contains_body)) {
        if (nodeid_is_pred(contains_body, self)) {
            TSetId pred = nodeid_pred_tset(contains_body, self);
            NodeId notpred = regex_builder_mk_pred_not(self, pred);
            NodeId node = regex_builder_mk_star(self, notpred);
            return regex_builder_init_as(self, key, node);
        }
        else if (nodeid_eq(contains_body, NODE_ID_END)) {
            return regex_builder_init_as(self, key, NODE_ID_BOT);
        }
    }

    if (regex_builder_get_kind(self, body) == KIND_COMPL) {
        return regex_builder_get_node(self, body)->left;
    }

    return regex_builder_get_node_id(self, key);
}

NodeId
regex_builder_mk_compl_outer(RegexBuilder *self, NodeId body)
{
    return regex_builder_mk_compl(self, body);
}

NodeId
regex_builder_extract_nulls_mask(RegexBuilder *self, NodeId body, Nullability mask)
{
    NullsId nid = regex_builder_get_nulls_id(self, body);
    const Nulls *nset = nulls_builder_get_set_ref(&self->mb.nb, nid);
    size_t len = nulls_set_len(nset);
    NodeId futures = NODE_ID_BOT;
    for (size_t i = 0; i < len; i++) {
        const NullState *np = nulls_set_get(nset, i);
        if (np == nullptr) break;
        NullState n = *np;
        if (!null_state_is_mask_nullable(&n, mask)) continue;
        NodeId eff;
        if (nullstate_rel(n) == 0) {
            eff = NODE_ID_EPS;
        }
        else {
            eff = regex_builder_mk_lookahead_internal(self, NODE_ID_EPS, NODE_ID_MISSING, nullstate_rel(n));
        }
        futures = regex_builder_mk_union(self, futures, eff);
    }
    return futures;
}

// ============================================================================
// Concat-rewrite cascade: strip_ts_max_len / peel_head_pred /
// strip_end_from_la_head / iter_inter_check_ts / attempt_rw_concat_2 /
// try_subsume_inter_union / attempt_rw_union_2 / attempt_rw_inter_2 /
// attempt_rw_unions.
// ============================================================================

static bool
regex_builder_strip_ts_max_len(RegexBuilder *self, NodeId node, uint32_t *out_total)
{
    NodeId cur = node;
    uint32_t total = 0;
    for (;;) {
        if (!nodeid_is_concat(cur, self)) return false;
        NodeId r = nodeid_right(cur, self);
        MinMax mm = regex_builder_get_min_max_length(self, nodeid_left(cur, self));
        uint32_t lmax = mm.max;
        if (lmax == UINT32_MAX) return false;
        uint64_t s = (uint64_t)total + (uint64_t)lmax;
        total = (s > UINT32_MAX) ? UINT32_MAX : (uint32_t)s;
        if (nodeid_eq(r, NODE_ID_TS)) {
            *out_total = total;
            return true;
        }
        cur = r;
    }
}

static bool
regex_builder_peel_head_pred(RegexBuilder *self, NodeId node, TSetId *out_p, NodeId *out_rest)
{
    if (nodeid_is_pred(node, self)) {
        *out_p    = nodeid_pred_tset(node, self);
        *out_rest = NODE_ID_EPS;
        return true;
    }
    if (nodeid_is_concat(node, self) && nodeid_is_pred(nodeid_left(node, self), self)) {
        *out_p    = nodeid_pred_tset(nodeid_left(node, self), self);
        *out_rest = nodeid_right(node, self);
        return true;
    }
    return false;
}

static NodeId
regex_builder_strip_end_from_la_head(RegexBuilder *self, NodeId node)
{
    NodeId head, rest;
    if (nodeid_is_concat(node, self)) {
        head = nodeid_left(node, self);
        rest = nodeid_right(node, self);
    }
    else {
        head = node;
        rest = NODE_ID_EPS;
    }
    if (!nodeid_is_kind(head, self, KIND_UNION)) return node;
    NodeId l = nodeid_left(head, self);
    if (!nodeid_is_end(l)) return node;
    NodeId r = nodeid_right(head, self);
    return regex_builder_mk_concat(self, r, rest);
}

typedef struct { bool alltopstar; } InterTSCtx;

static void inter_ts_visit(void *ctx_v, RegexBuilder *b, NodeId v);

static void
regex_builder_iter_inter_check_ts(RegexBuilder *self, NodeId head, InterTSCtx *ctx)
{
    regex_builder_iter_inter(self, head, ctx, inter_ts_visit);
}

static void
inter_ts_visit(void *ctx_v, RegexBuilder *b, NodeId v)
{
    InterTSCtx *ctx = ctx_v;
    ctx->alltopstar = regex_builder_ends_with_ts(b, v);
}

static bool
regex_builder_attempt_rw_concat_2(RegexBuilder *self, NodeId head, NodeId tail, NodeId *out)
{
    if (nodeid_is_lookbehind(tail, self)) {
        NodeId lbleft = regex_builder_mk_concat(self, head,
            nodeid_missing_to_eps(regex_builder_get_lookbehind_prev(self, tail)));
        NodeId result;
        n00b_regex_algebra_err_t e = regex_builder_mk_lookbehind_internal(self,
            nodeid_missing_to_eps(regex_builder_get_lookbehind_inner(self, tail)),
            lbleft, &result);
        if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return false;
        *out = result;
        return true;
    }
    if (nodeid_is_lookahead(head, self)) {
        NodeId la_tail = regex_builder_get_lookahead_tail(self, head);
        NodeId new_la_tail = regex_builder_mk_concat(self, nodeid_missing_to_eps(la_tail), tail);
        NodeId la_body = regex_builder_get_lookahead_inner(self, head);
        if (nodeid_is_never_nullable(new_la_tail, self)) {
            la_body = regex_builder_strip_end_from_la_head(self, la_body);
        }
        if (nodeid_eq(la_body, NODE_ID_BOT)) {
            *out = NODE_ID_BOT;
            return true;
        }
        TSetId p_l, p_b;
        NodeId body_rest, tail_rest;
        if (regex_builder_peel_head_pred(self, la_body, &p_l, &body_rest)
            && regex_builder_peel_head_pred(self, new_la_tail, &p_b, &tail_rest)) {
            TSetId p = solver_and_id(regex_builder_solver(self), p_l, p_b);
            NodeId merged = regex_builder_mk_pred(self, p);
            if (nodeid_eq(merged, NODE_ID_BOT)) {
                *out = NODE_ID_BOT;
                return true;
            }
            NodeId new_la;
            if (nodeid_eq(body_rest, NODE_ID_EPS)) {
                new_la = NODE_ID_EPS;
            }
            else {
                new_la = regex_builder_mk_lookahead(self, body_rest, NODE_ID_MISSING, 0);
            }
            NodeId after = regex_builder_mk_concat(self, new_la, tail_rest);
            *out = regex_builder_mk_concat(self, merged, after);
            return true;
        }

        if (nodeid_is_concat(la_body, self)
            && nodeid_is_end(nodeid_right(la_body, self))
            && nodeid_is_compl(nodeid_left(la_body, self), self)) {
            NodeId not_p_ts = nodeid_left(la_body, self);
            uint32_t p_max;
            if (regex_builder_strip_ts_max_len(self, nodeid_left(not_p_ts, self), &p_max)) {
                MinMax tail_mm = regex_builder_get_min_max_length(self, new_la_tail);
                uint32_t tail_min = tail_mm.min;
                if (p_max <= tail_min) {
                    *out = regex_builder_mk_inter(self, not_p_ts, new_la_tail);
                    return true;
                }
            }
        }

        if (nodeid_is_center_nullable(new_la_tail, self)) {
            *out = regex_builder_mk_lookahead_internal(self, la_body, new_la_tail, UINT32_MAX);
            return true;
        }
        uint32_t la_rel = regex_builder_get_lookahead_rel(self, head);
        if (nodeid_is_kind(new_la_tail, self, KIND_LOOKAHEAD)) {
            uint32_t tail_rel = regex_builder_get_lookahead_rel(self, new_la_tail);
            la_rel = tail_rel + la_rel;
        }
        else {
            la_rel = UINT32_MAX;
        }
        *out = regex_builder_mk_lookahead_internal(self, la_body, new_la_tail, la_rel);
        return true;
    }

    if (nodeid_is_kind(head, self, KIND_END) && nodeid_eq(tail, NODE_ID_TS)) {
        *out = head;
        return true;
    }
    if (nodeid_eq(head, NODE_ID_TS)
        && nullability_eq(regex_builder_nullability(self, tail), NULLABILITY_ALWAYS)) {
        *out = NODE_ID_TS;
        return true;
    }
    if (nodeid_eq(tail, NODE_ID_TS)
        && nullability_eq(regex_builder_nullability(self, head), NULLABILITY_ALWAYS)) {
        *out = NODE_ID_TS;
        return true;
    }
    if (nodeid_is_inter(head, self) && nodeid_eq(tail, NODE_ID_TS)) {
        InterTSCtx ctx = (InterTSCtx){ true };
        regex_builder_iter_inter_check_ts(self, head, &ctx);
        if (ctx.alltopstar) {
            *out = head;
            return true;
        }
    }
    if (nodeid_is_star(head, self) && nodeid_eq(head, tail)) {
        *out = head;
        return true;
    }
    return false;
}

typedef struct { NodeId target; } EqCtx;

static bool
eq_pred(NodeId v, void *ctx_v)
{
    return ((EqCtx *)ctx_v)->target.v == v.v;
}

typedef struct { NodeId *data; size_t len; size_t cap; } VecNodeIdLocal;

static void
regex_builder_collect_inter_components(RegexBuilder *self, NodeId node, VecNodeIdLocal *out)
{
    NodeId curr = node;
    while (nodeid_is_inter(curr, self)) {
        if (out->len == out->cap) {
            size_t nc = out->cap ? safe_mul_sz(out->cap, 2) : 8;
            grow_buf(NodeId, self->allocator, &out->data, &out->cap, out->len, nc);
        }
        out->data[out->len++] = regex_builder_get_left(self, curr);
        curr = regex_builder_get_right(self, curr);
    }
    if (out->len == out->cap) {
        size_t nc = out->cap ? safe_mul_sz(out->cap, 2) : 8;
        grow_buf(NodeId, self->allocator, &out->data, &out->cap, out->len, nc);
    }
    out->data[out->len++] = curr;
}

typedef struct {
    bool     has_prefix;
    TSetId   pred_set;
    NodeId   star_body;
    uint32_t count;
} PredChainStar;

static bool
regex_builder_as_pred_chain_star(RegexBuilder *self, NodeId node, PredChainStar *out)
{
    NodeId curr = node;
    bool has_prefix = nodeid_is_concat(curr, self)
        && nodeid_eq(regex_builder_get_left(self, curr), NODE_ID_TS);
    if (has_prefix) {
        curr = regex_builder_get_right(self, curr);
    }
    uint32_t count = 0;
    bool   pred_set_present = false;
    TSetId pred_set = (TSetId){ 0 };
    while (nodeid_is_concat(curr, self)) {
        NodeId head = regex_builder_get_left(self, curr);
        if (!nodeid_is_pred(head, self)) return false;
        TSetId ps = nodeid_pred_tset(head, self);
        if (!pred_set_present) {
            pred_set = ps;
            pred_set_present = true;
        }
        else if (pred_set.v != ps.v) {
            return false;
        }
        curr = regex_builder_get_right(self, curr);
        count += 1;
    }
    if (count == 0 || !nodeid_is_star(curr, self)) return false;
    out->has_prefix = has_prefix;
    out->pred_set   = pred_set;
    out->star_body  = curr;
    out->count      = count;
    return true;
}

static bool
is_sorted_subset_nodeids(const NodeId *sub, size_t sub_len,
                         const NodeId *sup, size_t sup_len)
{
    size_t j = 0;
    for (size_t i = 0; i < sub_len; i++) {
        NodeId s = sub[i];
        while (j < sup_len && sup[j].v < s.v) j++;
        if (j >= sup_len || sup[j].v != s.v) return false;
        j++;
    }
    return true;
}

static bool
regex_builder_try_subsume_inter_union(RegexBuilder *self, NodeId left, NodeId right, NodeId *out)
{
    if (!nodeid_is_inter(left, self) || !nodeid_is_inter(right, self)) return false;
    VecNodeIdLocal lc = (VecNodeIdLocal){};
    VecNodeIdLocal rc = (VecNodeIdLocal){};
    regex_builder_collect_inter_components(self, left, &lc);
    regex_builder_collect_inter_components(self, right, &rc);

    bool   result_set = false;
    NodeId result     = NODE_ID_MISSING;

    if (lc.len <= rc.len && is_sorted_subset_nodeids(lc.data, lc.len, rc.data, rc.len)) {
        result = left; result_set = true;
        goto cleanup;
    }
    if (rc.len <= lc.len && is_sorted_subset_nodeids(rc.data, rc.len, lc.data, lc.len)) {
        result = right; result_set = true;
        goto cleanup;
    }

    if (lc.len == rc.len) {
        ptrdiff_t diff_idx = -1;
        bool      conflict = false;
        for (size_t i = 0; i < lc.len; i++) {
            if (lc.data[i].v != rc.data[i].v) {
                if (diff_idx >= 0) { conflict = true; break; }
                diff_idx = (ptrdiff_t)i;
            }
        }
        if (!conflict && diff_idx >= 0) {
            NodeId a = lc.data[diff_idx];
            NodeId b = rc.data[diff_idx];
            PredChainStar pa, pb;
            if (regex_builder_as_pred_chain_star(self, a, &pa)
                && regex_builder_as_pred_chain_star(self, b, &pb)) {
                if (pa.has_prefix == pb.has_prefix
                    && pa.pred_set.v == pb.pred_set.v
                    && pa.star_body.v == pb.star_body.v
                    && pa.count != pb.count) {
                    result     = (pa.count < pb.count) ? left : right;
                    result_set = true;
                }
            }
        }
    }

cleanup:
    if (lc.data) n00b_free(lc.data);
    if (rc.data) n00b_free(rc.data);
    if (result_set) { *out = result; return true; }
    return false;
}

static bool
regex_builder_attempt_rw_union_2(RegexBuilder *self, NodeId left, NodeId right, NodeId *out)
{
    if (nodeid_eq(left, right)) { *out = left; return true; }

    EqCtx ec_left = (EqCtx){ left };
    if (nodeid_is_inter(right, self)
        && nodeid_any_inter_component(right, self, eq_pred, &ec_left)) {
        *out = left; return true;
    }
    if (nodeid_is_union(right, self)
        && nodeid_any_union_component(right, self, eq_pred, &ec_left)) {
        *out = right; return true;
    }

    if (nodeid_is_inter(left, self) && nodeid_is_inter(right, self)) {
        VecNodeIdLocal lconj = (VecNodeIdLocal){};
        regex_builder_collect_inter_components(self, left, &lconj);
        size_t lconj_initial = lconj.len;
        NodeId common = NODE_ID_TS;
        NodeId r_rest = NODE_ID_TS;
        NodeId cur = right;
        for (;;) {
            NodeId v;
            bool has_next;
            NodeId next_v = NODE_ID_MISSING;
            if (nodeid_kind(cur, self) == KIND_INTER) {
                v        = regex_builder_get_left(self, cur);
                next_v   = regex_builder_get_right(self, cur);
                has_next = true;
            }
            else {
                v        = cur;
                has_next = false;
            }
            ptrdiff_t pos = -1;
            for (size_t i = 0; i < lconj.len; i++) {
                if (lconj.data[i].v == v.v) { pos = (ptrdiff_t)i; break; }
            }
            if (pos >= 0) {
                lconj.data[pos] = lconj.data[lconj.len - 1];
                lconj.len--;
                common = regex_builder_mk_inter(self, v, common);
            }
            else {
                r_rest = regex_builder_mk_inter(self, v, r_rest);
            }
            if (has_next) cur = next_v;
            else break;
        }
        if (lconj.len < lconj_initial) {
            NodeId l_rest = NODE_ID_TS;
            for (size_t i = 0; i < lconj.len; i++) {
                l_rest = regex_builder_mk_inter(self, lconj.data[i], l_rest);
            }
            NodeId inner_union = regex_builder_mk_union(self, l_rest, r_rest);
            *out = regex_builder_mk_inter(self, common, inner_union);
            if (lconj.data) n00b_free(lconj.data);
            return true;
        }
        if (lconj.data) n00b_free(lconj.data);
    }

    if (nodeid_is_pred(left, self) && nodeid_is_pred(right, self)) {
        TSetId l = nodeid_pred_tset(left, self);
        TSetId r = nodeid_pred_tset(right, self);
        TSetId psi = solver_or_id(regex_builder_solver(self), l, r);
        *out = regex_builder_mk_pred(self, psi);
        return true;
    }

    if (nodeid_eq(left, NODE_ID_EPS)
        && regex_builder_get_extra(self, left) == 0
        && nullability_eq(regex_builder_nullability(self, right), NULLABILITY_ALWAYS)) {
        *out = right;
        return true;
    }

    if (nodeid_is_lookahead(left, self) && nodeid_is_lookahead(right, self)) {
        NodeId lb = regex_builder_get_left(self, left);
        NodeId lt = regex_builder_get_right(self, left);
        uint32_t lrel = nodeid_extra(left, self);
        NodeId rb = regex_builder_get_left(self, right);
        NodeId rt = regex_builder_get_right(self, right);
        uint32_t rrel = nodeid_extra(right, self);
        if (lrel == rrel && nodeid_is_missing(lt) && nodeid_is_missing(rt)) {
            NodeId unioned = regex_builder_mk_union(self, lb, rb);
            *out = regex_builder_mk_lookahead_internal(self, unioned, NODE_ID_MISSING, lrel);
            return true;
        }
    }

    if (nodeid_is_kind(right, self, KIND_CONCAT)) {
        if (nodeid_eq(left, NODE_ID_END)
            && nodeid_eq(regex_builder_get_left(self, right), NODE_ID_END)
            && nullability_has(regex_builder_nullability(self, right), NULLABILITY_END)) {
            *out = right;
            return true;
        }
        if (nodeid_eq(left, regex_builder_get_left(self, right))) {
            NodeId rhs = regex_builder_mk_union(self, NODE_ID_EPS, regex_builder_get_right(self, right));
            *out = regex_builder_mk_concat(self, left, rhs);
            return true;
        }
        if (nodeid_is_kind(left, self, KIND_CONCAT)) {
            NodeId head1 = regex_builder_get_left(self, left);
            NodeId head2 = regex_builder_get_left(self, right);
            if (nodeid_eq(head1, head2)) {
                NodeId t1 = regex_builder_get_right(self, left);
                NodeId t2 = regex_builder_get_right(self, right);
                if (nodeid_eq(head1, NODE_ID_TS)) {
                    if (nodeid_has_concat_tail(t2, self, t1)) { *out = left; return true; }
                    if (nodeid_has_concat_tail(t1, self, t2)) { *out = right; return true; }
                }
                NodeId un = regex_builder_mk_union(self, t1, t2);
                *out = regex_builder_mk_concat(self, regex_builder_get_left(self, left), un);
                return true;
            }
        }
        if (nodeid_is_pred(left, self) && nodeid_eq(left, regex_builder_get_left(self, right))) {
            NodeId un = regex_builder_mk_opt(self, regex_builder_get_right(self, right));
            *out = regex_builder_mk_concat(self, left, un);
            return true;
        }
    }

    if (nodeid_eq(left, NODE_ID_EPS) && nodeid_is_plus(right, self)) {
        *out = regex_builder_mk_star(self, regex_builder_get_left(self, right));
        return true;
    }

    if (nodeid_is_inter(left, self) && nodeid_is_inter(right, self)) {
        if (regex_builder_try_subsume_inter_union(self, left, right, out)) return true;
    }

    return false;
}

extern NodeId regex_builder_mk_plus(RegexBuilder *self, NodeId body);

static bool
regex_builder_attempt_rw_inter_2(RegexBuilder *self, NodeId left, NodeId right, NodeId *out)
{
    if (nodeid_eq(left, right)) { *out = left; return true; }

    EqCtx ec_left = (EqCtx){ left };
    if (nodeid_is_inter(right, self)
        && nodeid_any_inter_component(right, self, eq_pred, &ec_left)) {
        *out = right; return true;
    }
    if (nodeid_is_union(right, self)
        && nodeid_any_union_component(right, self, eq_pred, &ec_left)) {
        *out = left; return true;
    }

    if (nodeid_is_pred(left, self) && nodeid_is_pred(right, self)) {
        TSetId l = nodeid_pred_tset(left, self);
        TSetId r = nodeid_pred_tset(right, self);
        TSetId psi = solver_and_id(regex_builder_solver(self), l, r);
        *out = regex_builder_mk_pred(self, psi);
        return true;
    }

    NodeId pairs[2][2] = { { left, right }, { right, left } };
    for (int i = 0; i < 2; i++) {
        NodeId a = pairs[i][0];
        NodeId b = pairs[i][1];
        if (nodeid_is_pred(a, self) && nodeid_is_compl(b, self)) {
            NodeId cbody = regex_builder_get_left(self, b);
            if (nodeid_is_concat(cbody, self)
                && nodeid_eq(regex_builder_get_right(self, cbody), NODE_ID_TS)
                && nodeid_is_pred(regex_builder_get_left(self, cbody), self)) {
                TSetId q = nodeid_pred_tset(a, self);
                TSetId p = nodeid_pred_tset(regex_builder_get_left(self, cbody), self);
                TSetId notp = solver_not_id(regex_builder_solver(self), p);
                TSetId anded = solver_and_id(regex_builder_solver(self), q, notp);
                *out = regex_builder_mk_pred(self, anded);
                return true;
            }
        }
    }

    if (nodeid_is_concat(left, self) && nodeid_is_concat(right, self)) {
        if (nodeid_eq(regex_builder_get_left(self, left), regex_builder_get_left(self, right))
            && nodeid_is_pred(regex_builder_get_left(self, left), self)) {
            NodeId new_right = regex_builder_mk_inter(self,
                regex_builder_get_right(self, left),
                regex_builder_get_right(self, right));
            *out = regex_builder_mk_concat(self, regex_builder_get_left(self, left), new_right);
            return true;
        }
    }

    if (nodeid_is_compl(right, self) && nodeid_eq(regex_builder_get_left(self, right), left)) {
        *out = NODE_ID_BOT;
        return true;
    }

    if (nodeid_is_compl(left, self) && nodeid_is_compl(right, self)) {
        NodeId bodies = regex_builder_mk_union(self,
            regex_builder_get_left(self, left),
            regex_builder_get_left(self, right));
        *out = regex_builder_mk_compl_outer(self, bodies);
        return true;
    }

    if (nodeid_eq(left, NODE_ID_TOPPLUS)) {
        NodeId _ps_inner;
        if (nodeid_is_pred_star(right, self, &_ps_inner)) {
            *out = regex_builder_mk_plus(self, regex_builder_get_left(self, right));
            return true;
        }
        if (nodeid_is_never_nullable(right, self)) {
            *out = right;
            return true;
        }
        if (nodeid_is_kind(right, self, KIND_LOOKAHEAD)
            && nodeid_is_missing(regex_builder_get_lookahead_tail(self, right))) {
            *out = NODE_ID_BOT;
            return true;
        }
    }

    {
        bool l_is_la  = nodeid_is_lookahead(left, self);
        bool r_is_la  = nodeid_is_lookahead(right, self);
        bool l_is_cla = !l_is_la && nodeid_is_concat(left, self)
            && nodeid_is_lookahead(regex_builder_get_left(self, left), self);
        bool r_is_cla = !r_is_la && nodeid_is_concat(right, self)
            && nodeid_is_lookahead(regex_builder_get_left(self, right), self);
        if (l_is_la || r_is_la || l_is_cla || r_is_cla) {
            NodeId la_node, other, concat_body;
            if (r_is_la) {
                la_node = right; other = left; concat_body = NODE_ID_MISSING;
            }
            else if (l_is_la) {
                la_node = left; other = right; concat_body = NODE_ID_MISSING;
            }
            else if (r_is_cla) {
                la_node = regex_builder_get_left(self, right);
                other   = left;
                concat_body = regex_builder_get_right(self, right);
            }
            else {
                la_node = regex_builder_get_left(self, left);
                other   = right;
                concat_body = regex_builder_get_right(self, left);
            }
            NodeId la_body = regex_builder_get_left(self, la_node);
            NodeId la_tail = nodeid_missing_to_eps(regex_builder_get_lookahead_tail(self, la_node));
            NodeId inter_right;
            if (nodeid_is_missing(concat_body)) {
                inter_right = la_tail;
            }
            else {
                inter_right = regex_builder_mk_concat(self, la_tail, concat_body);
            }
            NodeId new_body = regex_builder_mk_inter(self, other, inter_right);
            NodeId la = regex_builder_mk_lookahead_internal(self, la_body, NODE_ID_MISSING, 0);
            *out = regex_builder_mk_concat(self, la, new_body);
            return true;
        }
    }

    if (regex_builder_get_kind(self, right) == KIND_COMPL) {
        NodeId compl_body = regex_builder_get_left(self, right);
        if (nodeid_eq(left, compl_body)) {
            *out = NODE_ID_BOT;
            return true;
        }
        if (nodeid_is_concat(compl_body, self)) {
            NodeId compl_head = regex_builder_get_left(self, compl_body);
            if (nodeid_eq(regex_builder_get_right(self, compl_body), NODE_ID_TS)
                && nodeid_eq(compl_head, left)) {
                *out = NODE_ID_BOT;
                return true;
            }
        }
    }

    {
        NodeId pleft, pright;
        NodeId _ps_l_inner, _ps_r_inner;
        if (nodeid_is_pred_star(left, self, &_ps_l_inner)) {
            pleft = regex_builder_get_left(self, left);
            if (nodeid_is_pred_star(right, self, &_ps_r_inner)) {
                pright = regex_builder_get_left(self, right);
                NodeId merged = regex_builder_mk_inter(self, pleft, pright);
                *out = regex_builder_mk_star(self, merged);
                return true;
            }
        }
    }

    {
        bool l_is_clb = nodeid_is_concat(left, self)
            && nodeid_is_lookbehind(regex_builder_get_left(self, left), self);
        bool r_is_clb = nodeid_is_concat(right, self)
            && nodeid_is_lookbehind(regex_builder_get_left(self, right), self);
        if (l_is_clb || r_is_clb) {
            NodeId lb, body;
            if (l_is_clb && r_is_clb) {
                NodeId lb1 = regex_builder_get_left(self, left);
                NodeId lb2 = regex_builder_get_left(self, right);
                NodeId inner = regex_builder_mk_inter(self,
                    regex_builder_get_lookbehind_inner(self, lb1),
                    regex_builder_get_lookbehind_inner(self, lb2));
                n00b_regex_algebra_err_t e = regex_builder_mk_lookbehind_internal(self, inner, NODE_ID_MISSING, &lb);
                (void)e;
                body = regex_builder_mk_inter(self,
                    regex_builder_get_right(self, left),
                    regex_builder_get_right(self, right));
            }
            else if (l_is_clb) {
                lb   = regex_builder_get_left(self, left);
                body = regex_builder_mk_inter(self, regex_builder_get_right(self, left), right);
            }
            else {
                lb   = regex_builder_get_left(self, right);
                body = regex_builder_mk_inter(self, left, regex_builder_get_right(self, right));
            }
            *out = regex_builder_mk_concat(self, lb, body);
            return true;
        }
    }

    {
        bool l_has_la = regex_builder_has_trailing_la(self, left);
        bool r_has_la = regex_builder_has_trailing_la(self, right);
        if (l_has_la || r_has_la) {
            NodeId body, la;
            if (l_has_la && r_has_la) {
                StripPair lp = regex_builder_strip_trailing_la(self, left);
                StripPair rp = regex_builder_strip_trailing_la(self, right);
                NodeId inner = regex_builder_mk_inter(self,
                    regex_builder_get_lookahead_inner(self, lp.la),
                    regex_builder_get_lookahead_inner(self, rp.la));
                la   = regex_builder_mk_lookahead_internal(self, inner, NODE_ID_MISSING, 0);
                body = regex_builder_mk_inter(self, lp.stripped, rp.stripped);
            }
            else if (l_has_la) {
                StripPair lp = regex_builder_strip_trailing_la(self, left);
                la   = lp.la;
                body = regex_builder_mk_inter(self, lp.stripped, right);
            }
            else {
                StripPair rp = regex_builder_strip_trailing_la(self, right);
                la   = rp.la;
                body = regex_builder_mk_inter(self, left, rp.stripped);
            }
            *out = regex_builder_mk_concat(self, body, la);
            return true;
        }
    }

    return false;
}

typedef struct {
    NodeId left;
    bool   found;
    NodeId target;
    NodeId rw;
} AttemptUnionsCtx;

static bool
attempt_unions_visitor(void *ctx_v, RegexBuilder *b, NodeId v)
{
    AttemptUnionsCtx *ctx = ctx_v;
    NodeId rw;
    if (regex_builder_attempt_rw_union_2(b, ctx->left, v, &rw)) {
        ctx->found  = true;
        ctx->target = v;
        ctx->rw     = rw;
        return false;
    }
    return true;
}

typedef struct {
    NodeId target;
    NodeId rw;
    NodeId new_union;
} RebuildUnionCtx;

static void
rebuild_union_visitor(void *ctx_v, RegexBuilder *b, NodeId v)
{
    RebuildUnionCtx *ctx = ctx_v;
    if (v.v == ctx->target.v) {
        ctx->new_union = regex_builder_mk_union(b, ctx->rw, ctx->new_union);
    }
    else {
        ctx->new_union = regex_builder_mk_union(b, v, ctx->new_union);
    }
}

static bool
regex_builder_attempt_rw_unions(RegexBuilder *self, NodeId left, NodeId right_union, NodeId *out)
{
    AttemptUnionsCtx ctx = (AttemptUnionsCtx){ left, false, NODE_ID_MISSING, NODE_ID_MISSING };
    regex_builder_iter_union_while(self, right_union, &ctx, attempt_unions_visitor);
    if (ctx.found) {
        RebuildUnionCtx rctx = (RebuildUnionCtx){ ctx.target, ctx.rw, NODE_ID_BOT };
        regex_builder_iter_union(self, right_union, &rctx, rebuild_union_visitor);
        *out = rctx.new_union;
        return true;
    }
    return false;
}

// ============================================================================
// mk_concat / mk_lookbehind / mk_lookbehind_internal / mk_lookahead /
// flatten_la_body / strip_trailing_ts / mk_lookahead_internal / mk_counted /
// prune_counted_chain.
// ============================================================================

NodeId
regex_builder_mk_concat(RegexBuilder *self, NodeId head, NodeId tail)
{
    n00b_require(self != nullptr, "regex_builder_mk_concat: self must not be null");
    n00b_require((size_t)head.v < self->array.len, "regex_builder_mk_concat: head NodeId out of bounds");
    n00b_require((size_t)tail.v < self->array.len, "regex_builder_mk_concat: tail NodeId out of bounds");
    NodeKey key = (NodeKey){
        .kind = KIND_CONCAT, .left = head, .right = tail, .extra = UINT32_MAX,
    };
    NodeId existing;
    if (node_key_map_get(self->index, key, &existing)) return existing;

    if (nodeid_eq(head, NODE_ID_BOT) || nodeid_eq(tail, NODE_ID_BOT)) return NODE_ID_BOT;
    if (nodeid_eq(head, NODE_ID_EPS)) return tail;
    if (nodeid_eq(tail, NODE_ID_EPS)) return head;

    if (nodeid_is_kind(head, self, KIND_CONCAT)) {
        NodeId left = nodeid_left(head, self);
        NodeId newright = regex_builder_mk_concat(self, nodeid_right(head, self), tail);
        NodeId updated = regex_builder_mk_concat(self, left, newright);
        return regex_builder_init_as(self, key, updated);
    }

    if (regex_builder_get_kind(self, head) == KIND_END
        && !regex_builder_is_nullable(self, tail, NULLABILITY_END)) {
        return NODE_ID_BOT;
    }

    if (nodeid_is_concat(tail, self)) {
        NodeId rw;
        if (regex_builder_attempt_rw_concat_2(self, head, nodeid_left(tail, self), &rw)) {
            NodeId upd = regex_builder_mk_concat(self, rw, nodeid_right(tail, self));
            return regex_builder_init_as(self, key, upd);
        }
    }

    NodeId rw;
    if (regex_builder_attempt_rw_concat_2(self, head, tail, &rw)) {
        return regex_builder_init_as(self, key, rw);
    }

    Kind hk = regex_builder_get_kind(self, head);
    Kind tk = regex_builder_get_kind(self, tail);
    if (hk == KIND_STAR && tk == KIND_CONCAT && nodeid_is_star(head, self)) {
        NodeId rl = nodeid_left(tail, self);
        if (nodeid_eq(head, rl)) {
            return regex_builder_init_as(self, key, tail);
        }
    }
    else if (tk == KIND_CONCAT) {
        NodeId h2 = regex_builder_mk_concat(self, head, nodeid_left(tail, self));
        NodeId tr = nodeid_right(tail, self);
        NodeId rw2;
        if (regex_builder_attempt_rw_concat_2(self, h2, tr, &rw2)) {
            return regex_builder_init_as(self, key, rw2);
        }
    }
    else if (nodeid_eq(head, NODE_ID_TS) && regex_builder_starts_with_ts(self, tail)) {
        return regex_builder_init_as(self, key, tail);
    }

    return regex_builder_init(self, key);
}

NodeId
regex_builder_mk_lookbehind(RegexBuilder *self, NodeId lb_body, NodeId lb_prev)
{
    n00b_require(self != nullptr, "regex_builder_mk_lookbehind: self must not be null");
    n00b_require((size_t)lb_body.v < self->array.len, "regex_builder_mk_lookbehind: lb_body NodeId out of bounds");
    n00b_require((size_t)lb_prev.v < self->array.len, "regex_builder_mk_lookbehind: lb_prev NodeId out of bounds");
    if (!regex_builder_starts_with_ts(self, lb_body)) {
        lb_body = regex_builder_mk_concat(self, NODE_ID_TS, lb_body);
    }
    NodeId out;
    n00b_regex_algebra_err_t e = regex_builder_mk_lookbehind_internal(self, lb_body, lb_prev, &out);
    (void)e;
    return out;
}

n00b_regex_algebra_err_t
regex_builder_mk_lookbehind_internal(RegexBuilder *self, NodeId lb_body, NodeId lb_prev, NodeId *out)
{
    n00b_require(self != nullptr, "regex_builder_mk_lookbehind_internal: self must not be null");
    n00b_require(out != nullptr, "regex_builder_mk_lookbehind_internal: out must not be null");
    n00b_require((size_t)lb_body.v < self->array.len, "regex_builder_mk_lookbehind_internal: lb_body NodeId out of bounds");
    n00b_require((size_t)lb_prev.v < self->array.len, "regex_builder_mk_lookbehind_internal: lb_prev NodeId out of bounds");
    if (nodeid_eq(lb_body, NODE_ID_BOT) || nodeid_eq(lb_prev, NODE_ID_BOT)) {
        *out = NODE_ID_BOT;
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    if (nodeid_eq(lb_body, NODE_ID_TS)) {
        *out = lb_prev;
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    if (nodeid_eq(lb_body, NODE_ID_EPS)) {
        if (nodeid_eq(lb_prev, NODE_ID_MISSING) || nodeid_eq(lb_prev, NODE_ID_EPS)) {
            *out = NODE_ID_EPS;
        }
        else {
            *out = lb_prev;
        }
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    NodeKey key = (NodeKey){
        .kind = KIND_LOOKBEHIND, .left = lb_body, .right = lb_prev, .extra = UINT32_MAX,
    };
    NodeId existing;
    if (node_key_map_get(self->index, key, &existing)) {
        *out = existing;
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    if (nodeid_eq(lb_prev, NODE_ID_TS)) {
        *out = regex_builder_mk_concat(self, lb_prev, lb_body);
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    *out = regex_builder_init(self, key);
    return N00B_REGEX_ALGEBRA_ERR_NONE;
}

extern NodeId regex_builder_flatten_la_body(RegexBuilder *self, NodeId node);

NodeId
regex_builder_mk_lookahead(RegexBuilder *self, NodeId la_body, NodeId la_tail, uint32_t rel)
{
    n00b_require(self != nullptr, "regex_builder_mk_lookahead: self must not be null");
    n00b_require((size_t)la_body.v < self->array.len, "regex_builder_mk_lookahead: la_body NodeId out of bounds");
    n00b_require((size_t)la_tail.v < self->array.len, "regex_builder_mk_lookahead: la_tail NodeId out of bounds");
    if (nodeid_is_missing(la_tail) && rel == 0) {
        la_body = regex_builder_flatten_la_body(self, la_body);
    }
    if (!regex_builder_ends_with_ts(self, la_body)) {
        la_body = regex_builder_mk_concat(self, la_body, NODE_ID_TS);
    }
    if (!nodeid_eq(la_tail, NODE_ID_MISSING)) {
        if (!nodeid_is_center_nullable(la_tail, self)) {
            rel = UINT32_MAX;
        }
    }
    return regex_builder_mk_lookahead_internal(self, la_body, la_tail, rel);
}

NodeId regex_builder_strip_trailing_ts(RegexBuilder *self, NodeId n);

NodeId
regex_builder_flatten_la_body(RegexBuilder *self, NodeId node)
{
    MetaFlags filter = metaflags_or(METAFLAGS_CONTAINS_LOOKBEHIND, METAFLAGS_CONTAINS_LOOKAHEAD);
    if (!metaflags_has(regex_builder_get_meta_flags(self, node), filter)) {
        return node;
    }
    switch (regex_builder_get_kind(self, node)) {
    case KIND_LOOKAHEAD:
        if (nodeid_is_missing(regex_builder_get_lookahead_tail(self, node))
            && regex_builder_get_lookahead_rel(self, node) == 0) {
            NodeId inner = regex_builder_get_lookahead_inner(self, node);
            inner = regex_builder_strip_trailing_ts(self, inner);
            return regex_builder_flatten_la_body(self, inner);
        }
        return node;
    case KIND_UNION: {
        NodeId l = regex_builder_flatten_la_body(self, nodeid_left(node, self));
        NodeId r = regex_builder_flatten_la_body(self, nodeid_right(node, self));
        return regex_builder_mk_union(self, l, r);
    }
    default:
        return node;
    }
}

NodeId
regex_builder_strip_trailing_ts(RegexBuilder *self, NodeId node)
{
    if (nodeid_is_concat(node, self) && nodeid_eq(nodeid_right(node, self), NODE_ID_TS)) {
        return nodeid_left(node, self);
    }
    return node;
}

NodeId
regex_builder_mk_lookahead_internal(RegexBuilder *self, NodeId la_body, NodeId la_tail, uint32_t rel)
{
    n00b_require(self != nullptr, "regex_builder_mk_lookahead_internal: self must not be null");
    n00b_require((size_t)la_body.v < self->array.len, "regex_builder_mk_lookahead_internal: la_body NodeId out of bounds");
    n00b_require((size_t)la_tail.v < self->array.len, "regex_builder_mk_lookahead_internal: la_tail NodeId out of bounds");
    NodeKey key = (NodeKey){
        .kind = KIND_LOOKAHEAD, .left = la_body, .right = la_tail, .extra = rel,
    };
    NodeId existing;
    if (node_key_map_get(self->index, key, &existing)) return existing;

    if (nodeid_eq(la_body, NODE_ID_TS)) {
        if (rel == 0) {
            return nodeid_missing_to_eps(la_tail);
        }
        return regex_builder_mk_lookahead_internal(self, NODE_ID_EPS, la_tail, rel);
    }
    if (nodeid_eq(la_body, NODE_ID_BOT) || nodeid_eq(la_tail, NODE_ID_BOT)) return NODE_ID_BOT;
    if (nodeid_is_missing(la_tail) && rel == UINT32_MAX) return NODE_ID_BOT;
    if (nodeid_eq(la_body, NODE_ID_EPS) && nodeid_is_missing(la_tail) && rel == 0) return la_body;

    if (nodeid_eq(la_tail, NODE_ID_TS)) {
        if (rel == 0 || rel == UINT32_MAX) {
            return regex_builder_mk_concat(self, la_body, NODE_ID_TS);
        }
    }

    if (rel == UINT32_MAX) {
        if (nodeid_is_missing(la_tail)) return NODE_ID_BOT;
        if (regex_builder_is_always_nullable(self, la_body)) {
            return nodeid_missing_to_eps(la_tail);
        }
        if (!nodeid_eq(la_tail, NODE_ID_MISSING)) {
            if (nodeid_is_compl_plus_end(la_body, self)) {
                uint32_t minlen = regex_builder_get_min_length_only(self, la_tail);
                if (minlen >= 1) return NODE_ID_BOT;
            }
        }
    }

    if (!nodeid_eq(la_tail, NODE_ID_MISSING) && nodeid_is_lookahead(la_tail, self)) {
        NodeId la_body2 = regex_builder_get_lookahead_inner(self, la_tail);
        NodeId body1_ts = regex_builder_mk_concat(self, la_body,  NODE_ID_TS);
        NodeId body2_ts = regex_builder_mk_concat(self, la_body2, NODE_ID_TS);
        NodeId new_la_body = regex_builder_mk_inter(self, body1_ts, body2_ts);
        uint32_t new_la_rel = regex_builder_get_lookahead_rel(self, la_tail);
        NodeId new_la_tail = regex_builder_get_lookahead_tail(self, la_tail);
        return regex_builder_mk_lookahead_internal(self, new_la_body, new_la_tail, new_la_rel);
    }

    if (nodeid_is_concat(la_body, self) && nodeid_eq(nodeid_left(la_body, self), NODE_ID_TS)) {
        NodeId la_body_right = nodeid_right(la_body, self);
        if (regex_builder_is_always_nullable(self, la_body_right)) {
            return regex_builder_mk_lookahead_internal(self, la_body_right, la_tail, rel);
        }
        if (nodeid_is_concat(la_body_right, self)
            && nodeid_eq(nodeid_left(la_body_right, self), NODE_ID_END)) {
            NodeId strippedanchor = regex_builder_mk_concat(self, NODE_ID_TS, nodeid_right(la_body_right, self));
            return regex_builder_mk_lookahead_internal(self, strippedanchor, la_tail, rel);
        }
    }

    if (!nodeid_eq(la_tail, NODE_ID_MISSING)) {
        if (regex_builder_get_kind(self, la_body) == KIND_CONCAT
            && regex_builder_get_kind(self, la_tail) == KIND_PRED) {
            NodeId lpred = nodeid_left(la_body, self);
            if (nodeid_is_pred(lpred, self)) {
                TSetId l = nodeid_pred_tset(lpred, self);
                TSetId r = nodeid_pred_tset(la_tail, self);
                TSetId psi_and = solver_and_id(regex_builder_solver(self), l, r);
                NodeId rewrite = regex_builder_mk_pred(self, psi_and);
                uint32_t new_rel = (rel == UINT32_MAX) ? 0 : rel + 1;
                NodeId new_right = regex_builder_mk_lookahead_internal(self,
                    nodeid_right(la_body, self), NODE_ID_MISSING, new_rel);
                return regex_builder_mk_concat(self, rewrite, new_right);
            }
        }
    }

    return regex_builder_get_node_id(self, key);
}

static NodeId regex_builder_prune_counted_chain(RegexBuilder *self, NodeId body, NodeId chain);

NodeId
regex_builder_mk_counted(RegexBuilder *self, NodeId body, NodeId chain, uint32_t packed)
{
    n00b_require(self != nullptr, "regex_builder_mk_counted: self must not be null");
    n00b_require((size_t)body.v < self->array.len, "regex_builder_mk_counted: body NodeId out of bounds");
    n00b_require((size_t)chain.v < self->array.len, "regex_builder_mk_counted: chain NodeId out of bounds");
    bool has_match = (packed >> 16) > 0;
    if (nodeid_eq(body, NODE_ID_BOT) && nodeid_eq(chain, NODE_ID_MISSING) && !has_match) {
        return NODE_ID_BOT;
    }
    chain = regex_builder_prune_counted_chain(self, body, chain);
    NodeKey key = (NodeKey){
        .kind = KIND_COUNTED, .left = body, .right = chain, .extra = packed,
    };
    NodeId existing;
    if (node_key_map_get(self->index, key, &existing)) return existing;
    return regex_builder_get_node_id(self, key);
}

static NodeId
regex_builder_prune_counted_chain(RegexBuilder *self, NodeId body, NodeId chain)
{
    if (nodeid_eq(chain, NODE_ID_MISSING) || nodeid_eq(body, NODE_ID_BOT)) return chain;
    if (!nullability_eq(regex_builder_nullability(self, body), NULLABILITY_NEVER)) return NODE_ID_MISSING;
    NodeId chain_body = nodeid_left(chain, self);
    if (nodeid_eq(chain_body, NODE_ID_BOT)) return chain;
    NodeId not_begins = regex_builder_mk_not_begins_with(self, body);
    NodeId inter = regex_builder_mk_inter(self, chain_body, not_begins);
    if (nodeid_eq(inter, NODE_ID_BOT)) {
        return regex_builder_prune_counted_chain(self, body, nodeid_right(chain, self));
    }
    return chain;
}

NodeId
regex_builder_mk_neg_lookahead(RegexBuilder *self, NodeId body, uint32_t rel)
{
    n00b_require(self != nullptr, "regex_builder_mk_neg_lookahead: self must not be null");
    n00b_require((size_t)body.v < self->array.len, "regex_builder_mk_neg_lookahead: body NodeId out of bounds");
    NodeId neg_inner = regex_builder_mk_concat(self, body, NODE_ID_TS);
    NodeId neg_part  = regex_builder_mk_compl(self, neg_inner);
    NodeId conc      = regex_builder_mk_concat(self, neg_part, NODE_ID_END);
    return regex_builder_mk_lookahead(self, conc, NODE_ID_MISSING, rel);
}

NodeId
regex_builder_mk_neg_lookbehind(RegexBuilder *self, NodeId body)
{
    n00b_require(self != nullptr, "regex_builder_mk_neg_lookbehind: self must not be null");
    n00b_require((size_t)body.v < self->array.len, "regex_builder_mk_neg_lookbehind: body NodeId out of bounds");
    if (regex_builder_get_node(self, body)->kind == KIND_PRED) {
        TSetId psi = nodeid_pred_tset(body, self);
        NodeId negated = regex_builder_mk_pred_not(self, psi);
        NodeId u = regex_builder_mk_union(self, NODE_ID_BEGIN, negated);
        NodeId out;
        n00b_regex_algebra_err_t e = regex_builder_mk_lookbehind_internal(self, u, NODE_ID_MISSING, &out);
        (void)e;
        return out;
    }
    NodeId uc = unicode_classes_utf8_char(self);
    NodeId neg = regex_builder_mk_compl(self, body);
    NodeId negated = regex_builder_mk_inter(self, neg, uc);
    NodeId u = regex_builder_mk_union(self, NODE_ID_BEGIN, negated);
    NodeId out;
    n00b_regex_algebra_err_t e = regex_builder_mk_lookbehind_internal(self, u, NODE_ID_MISSING, &out);
    (void)e;
    return out;
}

static void
temp_push_visit(void *ctx_v, RegexBuilder *b, NodeId v)
{
    (void)ctx_v;
    VecNodeId_push(&b->temp_vec, v, b->allocator);
}

NodeId
regex_builder_mk_union(RegexBuilder *self, NodeId left, NodeId right)
{
    n00b_require(self != nullptr, "regex_builder_mk_union: self must not be null");
    n00b_require((size_t)left.v  < self->array.len, "regex_builder_mk_union: left NodeId out of bounds");
    n00b_require((size_t)right.v < self->array.len, "regex_builder_mk_union: right NodeId out of bounds");
    if (left.v > right.v) return regex_builder_mk_union(self, right, left);
    NodeKey key = (NodeKey){
        .kind = KIND_UNION, .left = left, .right = right, .extra = UINT32_MAX,
    };
    NodeId existing;
    if (node_key_map_get(self->index, key, &existing)) return existing;

    if (nodeid_eq(left, right))           return regex_builder_init_as(self, key, left);
    if (nodeid_eq(left,  NODE_ID_BOT))    return regex_builder_init_as(self, key, right);
    if (nodeid_eq(right, NODE_ID_BOT))    return regex_builder_init_as(self, key, left);
    if (nodeid_eq(right, NODE_ID_TS))     return regex_builder_init_as(self, key, right);
    if (nodeid_eq(left,  NODE_ID_TS))     return regex_builder_init_as(self, key, left);

    Kind lk = regex_builder_get_kind(self, left);
    Kind rk = regex_builder_get_kind(self, right);
    if (lk == KIND_UNION) {
        regex_builder_iter_unions_b(self, left,  nullptr, temp_push_visit);
        regex_builder_iter_unions_b(self, right, nullptr, temp_push_visit);
        if (self->temp_vec.len > 1) {
            qsort(self->temp_vec.data, self->temp_vec.len, sizeof(NodeId), nodeid_cmp);
        }
        size_t  tree_len = self->temp_vec.len;
        NodeId *tree     = n00b_alloc_array_with_opts(NodeId, tree_len ? tree_len : 1, &(n00b_alloc_opts_t){.allocator = self->allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE});
        if (tree_len > 0) {
            memcpy(tree, self->temp_vec.data, tree_len * sizeof(NodeId));
        }
        self->temp_vec.len = 0;
        NodeId acc = NODE_ID_BOT;
        for (ptrdiff_t i = (ptrdiff_t)tree_len - 1; i >= 0; i--) {
            acc = regex_builder_mk_union(self, tree[i], acc);
        }
        n00b_free(tree);
        return regex_builder_init_as(self, key, acc);
    }
    else if (rk == KIND_UNION) {
        NodeId rleft = nodeid_left(right, self);
        if (left.v > rleft.v) {
            regex_builder_iter_unions_b(self, left,  nullptr, temp_push_visit);
            regex_builder_iter_unions_b(self, right, nullptr, temp_push_visit);
            if (self->temp_vec.len > 1) {
                qsort(self->temp_vec.data, self->temp_vec.len, sizeof(NodeId), nodeid_cmp);
            }
            size_t  tree_len = self->temp_vec.len;
            NodeId *tree     = n00b_alloc_array_with_opts(NodeId, tree_len ? tree_len : 1, &(n00b_alloc_opts_t){.allocator = self->allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE});
            if (tree_len > 0) {
                memcpy(tree, self->temp_vec.data, tree_len * sizeof(NodeId));
            }
            self->temp_vec.len = 0;
            NodeId acc = NODE_ID_BOT;
            for (ptrdiff_t i = (ptrdiff_t)tree_len - 1; i >= 0; i--) {
                acc = regex_builder_mk_union(self, tree[i], acc);
            }
            n00b_free(tree);
            return regex_builder_init_as(self, key, acc);
        }
        else {
            NodeId rw;
            if (regex_builder_attempt_rw_unions(self, left, right, &rw)) {
                return regex_builder_init_as(self, key, rw);
            }
        }
    }

    NodeId rw;
    if (regex_builder_attempt_rw_union_2(self, left, right, &rw)) {
        return regex_builder_init_as(self, key, rw);
    }
    return regex_builder_init(self, key);
}

NodeId
regex_builder_mk_inter(RegexBuilder *self, NodeId left_id, NodeId right_id)
{
    n00b_require(self != nullptr, "regex_builder_mk_inter: self must not be null");
    n00b_require((size_t)left_id.v  < self->array.len, "regex_builder_mk_inter: left NodeId out of bounds");
    n00b_require((size_t)right_id.v < self->array.len, "regex_builder_mk_inter: right NodeId out of bounds");
    if (nodeid_eq(left_id, right_id)) return left_id;
    if (nodeid_eq(left_id,  NODE_ID_BOT) || nodeid_eq(right_id, NODE_ID_BOT)) return NODE_ID_BOT;
    if (nodeid_eq(left_id,  NODE_ID_TS)) return right_id;
    if (nodeid_eq(right_id, NODE_ID_TS)) return left_id;
    if (left_id.v > right_id.v) return regex_builder_mk_inter(self, right_id, left_id);
    NodeKey key = (NodeKey){
        .kind = KIND_INTER, .left = left_id, .right = right_id, .extra = UINT32_MAX,
    };
    NodeId existing;
    if (node_key_map_get(self->index, key, &existing)) return existing;

    NodeId rw;
    if (regex_builder_attempt_rw_inter_2(self, left_id, right_id, &rw)) {
        return regex_builder_init_as(self, key, rw);
    }
    return regex_builder_init(self, key);
}

static NodeId
regex_builder_mk_unset(RegexBuilder *self, Kind kind)
{
    NodeKey node = (NodeKey){
        .kind = kind, .left = NODE_ID_MISSING, .right = NODE_ID_MISSING, .extra = UINT32_MAX,
    };
    return regex_builder_init(self, node);
}

NodeId
regex_builder_mk_plus(RegexBuilder *self, NodeId body_id)
{
    n00b_require(self != nullptr, "regex_builder_mk_plus: self must not be null");
    n00b_require((size_t)body_id.v < self->array.len, "regex_builder_mk_plus: body NodeId out of bounds");
    NodeId star = regex_builder_mk_star(self, body_id);
    return regex_builder_mk_concat(self, body_id, star);
}

NodeId
regex_builder_mk_repeat(RegexBuilder *self, NodeId body_id, uint32_t lower, uint32_t upper)
{
    n00b_require(self != nullptr, "regex_builder_mk_repeat: self must not be null");
    n00b_require((size_t)body_id.v < self->array.len, "regex_builder_mk_repeat: body NodeId out of bounds");
    if (upper < lower) return NODE_ID_BOT;
    uint32_t opt_count = upper - lower;
    NodeId opt = regex_builder_mk_opt(self, body_id);
    NodeId acc = NODE_ID_EPS;
    for (uint32_t i = 0; i < lower; i++) {
        acc = regex_builder_mk_concat(self, body_id, acc);
    }
    for (uint32_t i = 0; i < opt_count; i++) {
        acc = regex_builder_mk_concat(self, opt, acc);
    }
    return acc;
}

NodeId
regex_builder_mk_opt(RegexBuilder *self, NodeId body_id)
{
    n00b_require(self != nullptr, "regex_builder_mk_opt: self must not be null");
    n00b_require((size_t)body_id.v < self->array.len, "regex_builder_mk_opt: body NodeId out of bounds");
    return regex_builder_mk_union(self, NODE_ID_EPS, body_id);
}

NodeId
regex_builder_mk_star(RegexBuilder *self, NodeId body_id)
{
    n00b_require(self != nullptr, "regex_builder_mk_star: self must not be null");
    n00b_require((size_t)body_id.v < self->array.len, "regex_builder_mk_star: body NodeId out of bounds");
    NodeKey key = (NodeKey){
        .kind = KIND_STAR, .left = body_id, .right = NODE_ID_MISSING, .extra = 0,
    };
    NodeId existing;
    if (node_key_map_get(self->index, key, &existing)) return existing;
    if (nodeid_is_kind(body_id, self, KIND_STAR)) return body_id;
    return regex_builder_get_node_id(self, key);
}

// ============================================================================
// Nullability accessors at the public boundary.
// ============================================================================

Nullability
regex_builder_nullability_emptystring(const RegexBuilder *self, NodeId node_id)
{
    n00b_require(self != nullptr, "regex_builder_nullability_emptystring: self must not be null");
    n00b_require((size_t)node_id.v < self->array.len,
                 "regex_builder_nullability_emptystring: NodeId out of bounds");
    switch (regex_builder_get_kind(self, node_id)) {
    case KIND_END:   return NULLABILITY_EMPTYSTRING;
    case KIND_BEGIN: return NULLABILITY_EMPTYSTRING;
    case KIND_PRED:  return NULLABILITY_NEVER;
    case KIND_STAR:  return NULLABILITY_ALWAYS;
    case KIND_INTER:
    case KIND_CONCAT: {
        Nullability l = regex_builder_nullability_emptystring(self, nodeid_left(node_id, self));
        Nullability r = regex_builder_nullability_emptystring(self, nodeid_right(node_id, self));
        return nullability_and(l, r);
    }
    case KIND_UNION: {
        Nullability l = regex_builder_nullability_emptystring(self, nodeid_left(node_id, self));
        Nullability r = regex_builder_nullability_emptystring(self, nodeid_right(node_id, self));
        return nullability_or(l, r);
    }
    case KIND_COMPL:
        return nullability_not(regex_builder_nullability_emptystring(self, nodeid_left(node_id, self)));
    case KIND_LOOKBEHIND:
    case KIND_LOOKAHEAD:
    case KIND_COUNTED:
        return regex_builder_nullability_emptystring(self, nodeid_left(node_id, self));
    }
    return NULLABILITY_NEVER;
}

bool
regex_builder_any_nonbegin_nullable(const RegexBuilder *self, NodeId node_id)
{
    Nullability flags = metaflags_nullability(regex_builder_get_meta(self, node_id)->flags);
    return nullability_has(flags, nullability_or(NULLABILITY_CENTER, NULLABILITY_END));
}

Nullability
regex_builder_nullability(const RegexBuilder *self, NodeId node_id)
{
    n00b_require(self != nullptr, "regex_builder_nullability: self must not be null");
    n00b_require((size_t)node_id.v < self->array.len,
                 "regex_builder_nullability: NodeId out of bounds");
    return regex_builder_get_only_nullability(self, node_id);
}

bool
regex_builder_is_always_nullable(const RegexBuilder *self, NodeId node_id)
{
    return nullability_eq(
        nullability_and(regex_builder_get_only_nullability(self, node_id), NULLABILITY_ALWAYS),
        NULLABILITY_ALWAYS);
}

// ============================================================================
// Pretty-printer.  Uses an `n00b_buffer_t` (D12) with `.no_lock = true`
// for byte accumulation.  Final output is a NUL-terminated heap `char *`
// (managed by the n00b runtime — caller does not free).  Integer
// formatting goes through n00b_cformat instead of vsnprintf.
// ============================================================================

typedef struct PpBuf {
    n00b_buffer_t *buf;
} PpBuf;

static void
pp_init(PpBuf *p)
{
    p->buf = n00b_alloc(n00b_buffer_t);
    n00b_buffer_init(p->buf, .length = 0, .no_lock = true);
}

static void
pp_write_bytes(PpBuf *p, const char *bytes, size_t n)
{
    if (n == 0) return;
    n00b_buffer_concat(p->buf, n00b_buffer_from_bytes((char *)bytes, (int64_t)n));
}

static void
pp_write(PpBuf *p, const char *s)
{
    pp_write_bytes(p, s, strlen(s));
}

static void
pp_write_string(PpBuf *p, n00b_string_t *s)
{
    if (s == nullptr || s->u8_bytes == 0) return;
    pp_write_bytes(p, s->data, (size_t)s->u8_bytes);
}

static char *
pp_into_cstr(PpBuf *p)
{
    int64_t len = 0;
    char   *src = n00b_buffer_to_c(p->buf, &len);
    char   *out = n00b_alloc_array_with_opts(char, (size_t)len + 1, &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_NONE});
    if (len > 0 && src != nullptr) {
        memcpy(out, src, (size_t)len);
    }
    out[len] = '\0';
    return out;
}

constexpr TSetId TSETID_EMPTY = (TSetId){ 0 };
constexpr TSetId TSETID_FULL  = (TSetId){ 1 };

static void
pp_solver_into(const Solver *s, TSetId p, PpBuf *out)
{
    char *rendered = solver_pp(s, p);
    if (rendered) pp_write(out, rendered);
}

static void regex_builder_ppw(const RegexBuilder *self, PpBuf *s, NodeId node_id);

static void
regex_builder_ppt(const RegexBuilder *self, PpBuf *s, TRegexId term_id)
{
    const TRegex_TSetId *t = regex_builder_get_tregex(self, term_id);
    switch (t->selector) {
    case typehash(TRegex_leaf_t):
        regex_builder_ppw(self, s, n00b_variant_get(*t, TRegex_leaf_t).leaf);
        break;
    case typehash(TRegex_ite_t): {
        TRegex_ite_t _i = n00b_variant_get(*t, TRegex_ite_t);
        pp_write(s, "ITE(");
        pp_solver_into(regex_builder_solver_ref(self), _i.set, s);
        pp_write(s, ",");
        regex_builder_ppt(self, s, _i.then_id);
        pp_write(s, ",");
        regex_builder_ppt(self, s, _i.else_id);
        pp_write(s, ")");
        break;
    }
    }
}

static void
regex_builder_ppw(const RegexBuilder *self, PpBuf *s, NodeId node_id)
{
    if (nodeid_eq(node_id, NODE_ID_MISSING)) { pp_write(s, "MISSING"); return; }
    if (nodeid_eq(node_id, NODE_ID_BOT))     { pp_write(s, "\xE2\x8A\xA5"); return; }
    if (nodeid_eq(node_id, NODE_ID_TS))      { pp_write(s, "_*"); return; }
    if (nodeid_eq(node_id, NODE_ID_TOP))     { pp_write(s, "_"); return; }
    if (nodeid_eq(node_id, NODE_ID_EPS))     { pp_write(s, ""); return; }

    switch (regex_builder_get_kind(self, node_id)) {
    case KIND_END:   pp_write(s, "\\z"); return;
    case KIND_BEGIN: pp_write(s, "\\A"); return;
    case KIND_PRED: {
        TSetId psi = nodeid_pred_tset(node_id, self);
        if (psi.v == TSETID_EMPTY.v) { pp_write(s, "\xE2\x8A\xA5"); return; }
        if (psi.v == TSETID_FULL.v)  { pp_write(s, "_"); return; }
        pp_solver_into(regex_builder_solver_ref(self), psi, s);
        return;
    }
    case KIND_INTER: {
        pp_write(s, "(");
        regex_builder_ppw(self, s, nodeid_left(node_id, self));
        pp_write(s, "&");
        NodeId curr = nodeid_right(node_id, self);
        while (nodeid_is_inter(curr, self)) {
            NodeId n = nodeid_left(curr, self);
            regex_builder_ppw(self, s, n);
            pp_write(s, "&");
            curr = nodeid_right(curr, self);
        }
        regex_builder_ppw(self, s, curr);
        pp_write(s, ")");
        return;
    }
    case KIND_UNION: {
        NodeId left  = nodeid_left(node_id, self);
        NodeId right = nodeid_right(node_id, self);
        pp_write(s, "(");
        regex_builder_ppw(self, s, left);
        pp_write(s, "|");
        NodeId curr = right;
        while (regex_builder_get_kind(self, curr) == KIND_UNION) {
            NodeId n = nodeid_left(curr, self);
            regex_builder_ppw(self, s, n);
            pp_write(s, "|");
            curr = nodeid_right(curr, self);
        }
        regex_builder_ppw(self, s, curr);
        pp_write(s, ")");
        return;
    }
    case KIND_CONCAT: {
        NodeId left  = nodeid_left(node_id, self);
        NodeId right = nodeid_right(node_id, self);
        if (nodeid_is_star(right, self) && nodeid_eq(nodeid_left(right, self), left)) {
            regex_builder_ppw(self, s, left);
            pp_write(s, "+");
            return;
        }
        if (nodeid_is_concat(right, self)) {
            NodeId rl = nodeid_left(right, self);
            if (nodeid_is_star(rl, self) && nodeid_eq(nodeid_left(rl, self), left)) {
                regex_builder_ppw(self, s, left);
                pp_write(s, "+");
                regex_builder_ppw(self, s, nodeid_right(right, self));
                return;
            }
        }
        if (nodeid_is_concat(right, self) && nodeid_eq(nodeid_left(right, self), left)) {
            int num = 1;
            NodeId rcur = right;
            while (nodeid_is_concat(rcur, self) && nodeid_eq(nodeid_left(rcur, self), left)) {
                num += 1;
                rcur = nodeid_right(rcur, self);
            }
            NodeId inner;
            if (nodeid_is_opt_v(left, self, &inner)) {
                int inner_count = 0;
                NodeId right2 = rcur;
                while (nodeid_is_concat(right2, self)
                    && nodeid_eq(nodeid_left(right2, self), inner)) {
                    inner_count += 1;
                    right2 = nodeid_right(right2, self);
                }
                if (nodeid_eq(right2, inner)) {
                    inner_count += 1;
                    regex_builder_ppw(self, s, inner);
                    pp_write_string(s, n00b_cformat("{[|#|],[|#|]}",
                        (int64_t)inner_count, (int64_t)(inner_count + num)));
                    return;
                }
                if (inner_count > 0) {
                    regex_builder_ppw(self, s, inner);
                    pp_write_string(s, n00b_cformat("{[|#|],[|#|]}",
                        (int64_t)inner_count, (int64_t)(inner_count + num)));
                    regex_builder_ppw(self, s, right2);
                    return;
                }
            }
            regex_builder_ppw(self, s, left);
            if (nodeid_eq(rcur, left)) {
                num += 1;
                pp_write_string(s, n00b_cformat("{[|#|]}", (int64_t)num));
                return;
            }
            if (num <= 3 && nodeid_is_pred(left, self)) {
                for (int i = 1; i < num; i++) regex_builder_ppw(self, s, left);
                regex_builder_ppw(self, s, rcur);
                return;
            }
            pp_write_string(s, n00b_cformat("{[|#|]}", (int64_t)num));
            regex_builder_ppw(self, s, rcur);
            return;
        }
        regex_builder_ppw(self, s, left);
        regex_builder_ppw(self, s, right);
        return;
    }
    case KIND_STAR: {
        NodeId left = nodeid_left(node_id, self);
        Kind lk = regex_builder_get_kind(self, left);
        if (lk == KIND_CONCAT || lk == KIND_STAR || lk == KIND_COMPL) {
            pp_write(s, "(");
            regex_builder_ppw(self, s, left);
            pp_write(s, ")");
        }
        else {
            regex_builder_ppw(self, s, left);
        }
        pp_write(s, "*");
        return;
    }
    case KIND_COMPL:
        pp_write(s, "~(");
        regex_builder_ppw(self, s, nodeid_left(node_id, self));
        pp_write(s, ")");
        return;
    case KIND_LOOKBEHIND: {
        NodeId lbleft  = regex_builder_get_lookbehind_prev(self, node_id);
        NodeId lbinner = regex_builder_get_lookbehind_inner(self, node_id);
        if (!nodeid_eq(lbleft, NODE_ID_MISSING)) {
            pp_write(s, "\xE2\x9D\xAE");
            regex_builder_ppw(self, s, lbleft);
            pp_write(s, "\xE2\x9D\xAF");
        }
        pp_write(s, "(?<=");
        regex_builder_ppw(self, s, lbinner);
        pp_write(s, ")");
        return;
    }
    case KIND_LOOKAHEAD: {
        NodeId inner = regex_builder_get_lookahead_inner(self, node_id);
        pp_write(s, "(?=");
        regex_builder_ppw(self, s, inner);
        pp_write(s, ")");
        if (regex_builder_get_lookahead_rel(self, node_id) != 0) {
            pp_write(s, "{");
            uint32_t rel = regex_builder_get_lookahead_rel(self, node_id);
            if (rel == UINT32_MAX) {
                pp_write(s, "\xE2\x88\x85");
            }
            else {
                pp_write_string(s, n00b_cformat("[|#|]", (int64_t)rel));
            }
            pp_write(s, "}");
        }
        if (!nodeid_eq(nodeid_right(node_id, self), NODE_ID_MISSING)) {
            pp_write(s, "\xE2\x9D\xAE");
            regex_builder_ppw(self, s, nodeid_right(node_id, self));
            pp_write(s, "\xE2\x9D\xAF");
        }
        return;
    }
    case KIND_COUNTED: {
        NodeId body = nodeid_left(node_id, self);
        uint32_t packed = regex_builder_get_extra(self, node_id);
        uint32_t step = packed & 0xFFFF;
        uint32_t best = packed >> 16;
        pp_write(s, "#(");
        regex_builder_ppw(self, s, body);
        pp_write_string(s, n00b_cformat(")s[|#|]b[|#|]", (int64_t)step, (int64_t)best));
        return;
    }
    }
}

char *
regex_builder_pp(const RegexBuilder *self, NodeId node_id)
{
    n00b_require(self != nullptr, "regex_builder_pp: self must not be null");
    n00b_require((size_t)node_id.v < self->array.len, "regex_builder_pp: NodeId out of bounds");
    PpBuf b; pp_init(&b);
    regex_builder_ppw(self, &b, node_id);
    return pp_into_cstr(&b);
}

char *
regex_builder_ppt_str(const RegexBuilder *self, TRegexId term_id)
{
    n00b_require(self != nullptr, "regex_builder_ppt_str: self must not be null");
    n00b_require((size_t)term_id.v < self->tr_array.len,
                 "regex_builder_ppt_str: TRegexId out of bounds");
    PpBuf b; pp_init(&b);
    regex_builder_ppt(self, &b, term_id);
    return pp_into_cstr(&b);
}

// ============================================================================
// mk_begins_with / mk_not_begins_with / mk_pred_not / mk_u8 / mk_range_u8 /
// mk_ranges_u8 / extract_literal_prefix / mk_bytestring / mk_string.
// ============================================================================

NodeId
regex_builder_mk_begins_with(RegexBuilder *self, NodeId node)
{
    n00b_require(self != nullptr, "regex_builder_mk_begins_with: self must not be null");
    n00b_require((size_t)node.v < self->array.len, "regex_builder_mk_begins_with: NodeId out of bounds");
    return regex_builder_mk_concat(self, node, NODE_ID_TS);
}

NodeId
regex_builder_mk_not_begins_with(RegexBuilder *self, NodeId node)
{
    n00b_require(self != nullptr, "regex_builder_mk_not_begins_with: self must not be null");
    n00b_require((size_t)node.v < self->array.len, "regex_builder_mk_not_begins_with: NodeId out of bounds");
    NodeId node_ts = regex_builder_mk_concat(self, node, NODE_ID_TS);
    return regex_builder_mk_compl(self, node_ts);
}

NodeId
regex_builder_mk_pred_not(RegexBuilder *self, TSetId set)
{
    n00b_require(self != nullptr, "regex_builder_mk_pred_not: self must not be null");
    TSetId notset = solver_not_id(regex_builder_solver(self), set);
    return regex_builder_mk_pred(self, notset);
}

NodeId
regex_builder_mk_u8(RegexBuilder *self, uint8_t c)
{
    n00b_require(self != nullptr, "regex_builder_mk_u8: self must not be null");
    TSetId set_id = solver_u8_to_set_id(regex_builder_solver(self), c);
    return regex_builder_mk_pred(self, set_id);
}

NodeId
regex_builder_mk_range_u8(RegexBuilder *self, uint8_t start, uint8_t end_inclusive)
{
    n00b_require(self != nullptr, "regex_builder_mk_range_u8: self must not be null");
    TSetId rs = solver_range_to_set_id(regex_builder_solver(self), start, end_inclusive);
    return regex_builder_mk_pred(self, rs);
}

NodeId
regex_builder_mk_ranges_u8(RegexBuilder *self, const range_u8_t *ranges, size_t n)
{
    n00b_require(self != nullptr, "regex_builder_mk_ranges_u8: self must not be null");
    n00b_require(ranges != nullptr, "regex_builder_mk_ranges_u8: ranges must not be null");
    n00b_require(n > 0, "regex_builder_mk_ranges_u8: n must be > 0");
    NodeId node = regex_builder_mk_range_u8(self, ranges[0].lo, ranges[0].hi);
    for (size_t i = 1; i < n; i++) {
        NodeId r = regex_builder_mk_range_u8(self, ranges[i].lo, ranges[i].hi);
        node = regex_builder_mk_union(self, node, r);
    }
    return node;
}

LiteralPrefix
regex_builder_extract_literal_prefix(const RegexBuilder *self, NodeId node)
{
    n00b_require(self != nullptr, "regex_builder_extract_literal_prefix: self must not be null");
    n00b_require((size_t)node.v < self->array.len,
                 "regex_builder_extract_literal_prefix: NodeId out of bounds");
    LiteralPrefix out = (LiteralPrefix){};
    size_t cap = 0;
    NodeId curr = node;
    for (;;) {
        if (nodeid_eq(curr, NODE_ID_EPS)) {
            out.full = (out.len > 0);
            return out;
        }
        if (nodeid_eq(curr, NODE_ID_BOT)) break;
        if (nodeid_is_pred(curr, self)) {
            uint8_t byte;
            TSetId p = (TSetId){ regex_builder_get_extra(self, curr) };
            if (solver_single_byte(regex_builder_solver_ref(self), p, &byte)) {
                if (out.len == cap) {
                    size_t nc = cap ? safe_mul_sz(cap, 2) : 8;
                    grow_buf(uint8_t, self->allocator, &out.data, &cap, out.len, nc);
                }
                out.data[out.len++] = byte;
                out.full = true;
                return out;
            }
            break;
        }
        if (!nodeid_is_concat(curr, self)) break;
        NodeId left = nodeid_left(curr, self);
        if (!nodeid_is_pred(left, self)) break;
        uint8_t byte;
        TSetId p = (TSetId){ regex_builder_get_extra(self, left) };
        if (!solver_single_byte(regex_builder_solver_ref(self), p, &byte)) break;
        if (out.len == cap) {
            size_t nc = cap ? safe_mul_sz(cap, 2) : 8;
            grow_buf(uint8_t, self->allocator, &out.data, &cap, out.len, nc);
        }
        out.data[out.len++] = byte;
        curr = nodeid_right(curr, self);
    }
    out.full = false;
    return out;
}

NodeId
regex_builder_mk_bytestring(RegexBuilder *self, const uint8_t *raw, size_t n)
{
    n00b_require(self != nullptr, "regex_builder_mk_bytestring: self must not be null");
    n00b_require(raw != nullptr || n == 0,
                 "regex_builder_mk_bytestring: raw must not be null when n > 0");
    NodeId result = NODE_ID_EPS;
    for (ptrdiff_t i = (ptrdiff_t)n - 1; i >= 0; i--) {
        NodeId nd = regex_builder_mk_u8(self, raw[i]);
        result = regex_builder_mk_concat(self, nd, result);
    }
    return result;
}

NodeId
regex_builder_mk_string(RegexBuilder *self, const char *raw)
{
    n00b_require(self != nullptr, "regex_builder_mk_string: self must not be null");
    if (raw == nullptr) return NODE_ID_EPS;
    return regex_builder_mk_bytestring(self, (const uint8_t *)raw, strlen(raw));
}

// ============================================================================
// NodeIdMap (prune-memo facade) and U32Map (for prune_rec FWD `best`).
// ============================================================================

struct NodeIdMap {
    NodeIdHashMap    *m;
    n00b_allocator_t *allocator;
};

static inline NodeIdHashMap *
nimap_ensure(NodeIdMap *m)
{
    if (m->m == nullptr) m->m = NodeIdHashMap_new(m->allocator);
    return m->m;
}

static bool
nimap_get(const NodeIdMap *m, NodeId k, NodeId *out)
{
    if (m->m == nullptr) return false;
    return NodeIdHashMap_get(m->m, k, out);
}

static void
nimap_insert(NodeIdMap *m, NodeId k, NodeId v)
{
    NodeIdHashMap_insert(nimap_ensure(m), k, v);
}

NodeIdMap *
regex_builder_prune_memo_new(n00b_allocator_t *allocator)
{
    NodeIdMap *m = n00b_alloc_with_opts(
        NodeIdMap, &(n00b_alloc_opts_t){.allocator = allocator});
    m->allocator = allocator;
    return m;
}

void
regex_builder_prune_memo_free(NodeIdMap *memo)
{
    // The dict's internal storage is GC-managed; no explicit free here.
    // Leaving the wrapper alive after a call to _free would be a misuse,
    // but freeing the wrapper itself is unnecessary (also GC-managed).
    (void)memo;
}

typedef struct U32Map {
    NodeIdU32Map     *m;
    n00b_allocator_t *allocator;
} U32Map;

static bool
u32map_get(const U32Map *m, NodeId k, uint32_t *out)
{
    if (m->m == nullptr) return false;
    return NodeIdU32Map_get(m->m, k, out);
}

static void
u32map_insert(U32Map *m, NodeId k, uint32_t v)
{
    if (m->m == nullptr) ((U32Map *)m)->m = NodeIdU32Map_new(m->allocator);
    NodeIdU32Map_insert(m->m, k, v);
}

// ============================================================================
// simplify_fwd_initial / simplify_rev_initial.
// ============================================================================

static NodeId
regex_builder_try_begin_neg_pred_rewrite(RegexBuilder *self, NodeId r, NodeId *out)
{
    if (!nodeid_is_concat(r, self)) return NODE_ID_MISSING;
    NodeId begin = nodeid_left(r, self);
    NodeId mid_tail = nodeid_right(r, self);
    if (!nodeid_is_begin(begin)) return NODE_ID_MISSING;
    if (!nodeid_is_concat(mid_tail, self)) return NODE_ID_MISSING;
    NodeId neg = nodeid_left(mid_tail, self);
    NodeId tail = nodeid_right(mid_tail, self);
    if (regex_builder_get_kind(self, neg) != KIND_COMPL) return NODE_ID_MISSING;
    NodeId inside = nodeid_left(neg, self);
    if (!nodeid_is_concat(inside, self)) return NODE_ID_MISSING;
    NodeId ts_part = nodeid_left(inside, self);
    NodeId c_pred  = nodeid_right(inside, self);
    if (!nodeid_eq(ts_part, NODE_ID_TS) || !nodeid_is_pred(c_pred, self)) return NODE_ID_MISSING;
    TSetId c_tset = nodeid_pred_tset(c_pred, self);
    NodeId not_c = regex_builder_mk_pred_not(self, c_tset);
    NodeId left_branch = regex_builder_mk_concat(self, NODE_ID_BEGIN, tail);
    NodeId not_c_tail  = regex_builder_mk_concat(self, not_c, tail);
    NodeId right_branch = regex_builder_mk_concat(self, NODE_ID_TS, not_c_tail);
    *out = regex_builder_mk_union(self, left_branch, right_branch);
    return *out;
}

static NodeId
regex_builder_strip_la_body_end(RegexBuilder *self, NodeId n)
{
    if (!nodeid_is_concat(n, self)) return n;
    NodeId l = nodeid_left(n, self);
    NodeId r = nodeid_right(n, self);
    if (nodeid_eq(l, NODE_ID_TS) && nodeid_eq(r, NODE_ID_END)) return NODE_ID_TS;
    NodeId new_r = regex_builder_strip_la_body_end(self, r);
    if (nodeid_eq(new_r, r)) return n;
    return regex_builder_mk_concat(self, l, new_r);
}

typedef struct VecParts { NodeId *data; size_t len; size_t cap; } VecParts;

static void
parts_push_visit(void *ctx_v, RegexBuilder *b, NodeId v)
{
    VecParts *p = ctx_v;
    if (p->len == p->cap) {
        size_t nc = p->cap ? safe_mul_sz(p->cap, 2) : 8;
        grow_buf(NodeId, b->allocator, &p->data, &p->cap, p->len, nc);
    }
    p->data[p->len++] = v;
}

static NodeId regex_builder_simplify_fwd_initial_rec(RegexBuilder *self, NodeId node_id, NodeIdMap *memo);

NodeId
regex_builder_simplify_fwd_initial(RegexBuilder *self, NodeId node_id)
{
    n00b_require(self != nullptr, "regex_builder_simplify_fwd_initial: self must not be null");
    n00b_require((size_t)node_id.v < self->array.len,
                 "regex_builder_simplify_fwd_initial: NodeId out of bounds");
    NodeIdMap memo = (NodeIdMap){.allocator = self->allocator};
    if (regex_builder_get_kind(self, node_id) == KIND_CONCAT) {
        NodeId l = regex_builder_simplify_fwd_initial_rec(self, nodeid_left(node_id, self), &memo);
        NodeId r = regex_builder_simplify_fwd_initial_rec(self, nodeid_right(node_id, self), &memo);
        if (nodeid_is_concat(r, self)) {
            if (nodeid_is_ts(nodeid_left(r, self))
                && !nodeid_is_lookahead(nodeid_right(r, self), self)) {
                if (nodeid_is_begin_nullable(l, self)) {
                    return r;
                }
            }
        }
    }
    return regex_builder_simplify_fwd_initial_rec(self, node_id, &memo);
}

static NodeId
regex_builder_simplify_fwd_initial_rec(RegexBuilder *self, NodeId node_id, NodeIdMap *memo)
{
    NodeId cached;
    if (nimap_get(memo, node_id, &cached)) return cached;
    NodeId out;
    switch (regex_builder_get_kind(self, node_id)) {
    case KIND_UNION: {
        VecParts parts = (VecParts){};
        regex_builder_iter_unions_b(self, node_id, &parts, parts_push_visit);
        for (size_t i = 0; i < parts.len; i++) {
            parts.data[i] = regex_builder_simplify_fwd_initial_rec(self, parts.data[i], memo);
        }
        NodeId acc = NODE_ID_BOT;
        for (ptrdiff_t i = (ptrdiff_t)parts.len - 1; i >= 0; i--) {
            acc = regex_builder_mk_union(self, parts.data[i], acc);
        }
        if (parts.data) n00b_free(parts.data);
        out = acc;
        break;
    }
    case KIND_CONCAT: {
        NodeId l = regex_builder_simplify_fwd_initial_rec(self, nodeid_left(node_id, self), memo);
        NodeId r = regex_builder_simplify_fwd_initial_rec(self, nodeid_right(node_id, self), memo);
        if (nodeid_eq(l, NODE_ID_TS) && nodeid_is_lookahead(r, self)
            && nodeid_is_missing(regex_builder_get_lookahead_tail(self, r))
            && regex_builder_get_lookahead_rel(self, r) == 0) {
            NodeId body = regex_builder_get_lookahead_inner(self, r);
            if (regex_builder_is_nullable(self, body, NULLABILITY_END)) {
                out = NODE_ID_TS;
                break;
            }
        }
        if (!nodeid_eq(l, NODE_ID_TS)) {
            out = regex_builder_mk_concat(self, l, r);
            break;
        }
        NodeId rw;
        if (regex_builder_try_begin_neg_pred_rewrite(self, r, &rw).v != NODE_ID_MISSING.v) {
            out = rw;
            break;
        }
        NodeId head, tail;
        if (nodeid_is_concat(r, self)) {
            head = nodeid_left(r, self);
            tail = nodeid_right(r, self);
        }
        else {
            head = r;
            tail = NODE_ID_EPS;
        }
        if (regex_builder_get_kind(self, head) != KIND_UNION) {
            out = regex_builder_mk_concat(self, l, r);
            break;
        }
        if (!nodeid_is_begin(nodeid_left(head, self))) {
            out = regex_builder_mk_concat(self, l, r);
            break;
        }
        NodeId y = nodeid_right(head, self);
        if (!nodeid_is_pred(y, self)) {
            out = regex_builder_mk_concat(self, l, r);
            break;
        }
        if (nodeid_is_concat(tail, self)) {
            NodeId tl = nodeid_left(tail, self);
            NodeId tr = nodeid_right(tail, self);
            TSetId y_tset = nodeid_pred_tset(y, self);
            bool covers_all = false;
            if (nodeid_eq(tl, NODE_ID_TS)) {
                covers_all = true;
            }
            else {
                NodeId _ps_inner;
                if (nodeid_is_pred_star(tl, self, &_ps_inner)) {
                    NodeId x_pred = nodeid_left(tl, self);
                    TSetId x_ts = nodeid_pred_tset(x_pred, self);
                    TSetId combined = solver_or_id(regex_builder_solver(self), x_ts, y_tset);
                    covers_all = solver_is_full_id(regex_builder_solver(self), combined);
                }
            }
            if (covers_all) {
                out = regex_builder_mk_concat(self, NODE_ID_TS, tr);
                break;
            }
        }
        out = regex_builder_mk_concat(self, l, r);
        break;
    }
    default:
        out = node_id;
        break;
    }
    nimap_insert(memo, node_id, out);
    return out;
}

static NodeId regex_builder_simplify_rev_initial_rec(RegexBuilder *self, NodeId node_id, NodeIdMap *memo);

NodeId
regex_builder_simplify_rev_initial(RegexBuilder *self, NodeId node_id)
{
    NodeIdMap memo = (NodeIdMap){.allocator = self->allocator};
    return regex_builder_simplify_rev_initial_rec(self, node_id, &memo);
}

static NodeId
regex_builder_simplify_rev_initial_rec(RegexBuilder *self, NodeId node_id, NodeIdMap *memo)
{
    NodeId cached;
    if (nimap_get(memo, node_id, &cached)) return cached;
    NodeId out;
    switch (regex_builder_get_kind(self, node_id)) {
    case KIND_UNION: {
        VecParts parts = (VecParts){};
        regex_builder_iter_unions_b(self, node_id, &parts, parts_push_visit);
        for (size_t i = 0; i < parts.len; i++) {
            parts.data[i] = regex_builder_simplify_rev_initial_rec(self, parts.data[i], memo);
        }
        NodeId acc = NODE_ID_BOT;
        for (ptrdiff_t i = (ptrdiff_t)parts.len - 1; i >= 0; i--) {
            acc = regex_builder_mk_union(self, parts.data[i], acc);
        }
        if (parts.data) n00b_free(parts.data);
        out = acc;
        break;
    }
    case KIND_CONCAT: {
        NodeId l = regex_builder_simplify_rev_initial_rec(self, nodeid_left(node_id, self), memo);
        NodeId r = regex_builder_simplify_rev_initial_rec(self, nodeid_right(node_id, self), memo);
        if (!nodeid_eq(l, NODE_ID_TS)) { out = regex_builder_mk_concat(self, l, r); break; }
        NodeId rw;
        if (regex_builder_try_begin_neg_pred_rewrite(self, r, &rw).v != NODE_ID_MISSING.v) {
            out = rw; break;
        }
        NodeId head, tail;
        if (nodeid_is_concat(r, self)) {
            head = nodeid_left(r, self); tail = nodeid_right(r, self);
        }
        else {
            head = r; tail = NODE_ID_EPS;
        }
        if (nodeid_is_begin(head)) { out = r; break; }
        if (regex_builder_get_kind(self, head) != KIND_UNION) {
            out = regex_builder_mk_concat(self, l, r); break;
        }
        if (!nodeid_is_begin(nodeid_left(head, self))) {
            out = regex_builder_mk_concat(self, l, r); break;
        }
        NodeId y = nodeid_right(head, self);
        if (!nodeid_is_pred(y, self)) {
            out = regex_builder_mk_concat(self, l, r); break;
        }
        if (nodeid_is_concat(tail, self)) {
            NodeId tl = nodeid_left(tail, self);
            NodeId tr = nodeid_right(tail, self);
            TSetId y_tset = nodeid_pred_tset(y, self);
            bool covers_all = false;
            if (nodeid_eq(tl, NODE_ID_TS)) {
                covers_all = true;
            }
            else {
                NodeId _ps_inner;
                if (nodeid_is_pred_star(tl, self, &_ps_inner)) {
                    NodeId x_pred = nodeid_left(tl, self);
                    TSetId x_ts = nodeid_pred_tset(x_pred, self);
                    TSetId combined = solver_or_id(regex_builder_solver(self), x_ts, y_tset);
                    covers_all = solver_is_full_id(regex_builder_solver(self), combined);
                }
            }
            if (covers_all) { out = regex_builder_mk_concat(self, NODE_ID_TS, tr); break; }
        }
        out = regex_builder_mk_concat(self, l, r);
        break;
    }
    default:
        out = node_id;
        break;
    }
    nimap_insert(memo, node_id, out);
    return out;
}

// ============================================================================
// prune_rec / prune_fwd / prune_rev.
// ============================================================================

static NodeId
regex_builder_prune_rec(RegexBuilder *self, NodeId node_id, NodeIdMap *memo, bool fwd)
{
    if (nodeid_eq(node_id, NODE_ID_MISSING)) return node_id;
    NodeId cached;
    if (nimap_get(memo, node_id, &cached)) return cached;
    NodeId l = nodeid_left(node_id, self);
    NodeId r = nodeid_right(node_id, self);
    NodeId out;
    switch (nodeid_kind(node_id, self)) {
    case KIND_UNION: {
        NodeId pl = regex_builder_prune_rec(self, l, memo, fwd);
        NodeId pr = regex_builder_prune_rec(self, r, memo, fwd);
        VecParts parts = (VecParts){};
        parts_push_visit(&parts, self, pl);
        regex_builder_iter_unions_b(self, pr, &parts, parts_push_visit);
        for (size_t i = 0; i < parts.len; i++) {
            parts.data[i] = regex_builder_prune_rec(self, parts.data[i], memo, fwd);
        }
        if (fwd) {
            U32Map best = (U32Map){.allocator = self->allocator};
            for (size_t i = 0; i < parts.len; i++) {
                NodeId p = parts.data[i];
                if (nodeid_is_lookahead(p, self)
                    && nodeid_eq(regex_builder_get_lookahead_tail(self, p), NODE_ID_MISSING)) {
                    NodeId body = regex_builder_get_lookahead_inner(self, p);
                    uint32_t rel = regex_builder_get_lookahead_rel(self, p);
                    uint32_t cur;
                    if (u32map_get(&best, body, &cur)) {
                        if (rel < cur) u32map_insert(&best, body, rel);
                    }
                    else {
                        u32map_insert(&best, body, rel);
                    }
                }
            }
            NodeId acc = NODE_ID_BOT;
            for (ptrdiff_t i = (ptrdiff_t)parts.len - 1; i >= 0; i--) {
                NodeId p = parts.data[i];
                if (nodeid_is_lookahead(p, self)
                    && nodeid_eq(regex_builder_get_lookahead_tail(self, p), NODE_ID_MISSING)) {
                    NodeId body = regex_builder_get_lookahead_inner(self, p);
                    uint32_t br;
                    if (u32map_get(&best, body, &br)) {
                        if (regex_builder_get_lookahead_rel(self, p) != br) continue;
                    }
                }
                acc = regex_builder_mk_union(self, p, acc);
            }
            if (parts.data) n00b_free(parts.data);
            out = acc;
        }
        else {
            NodeId acc = NODE_ID_BOT;
            for (ptrdiff_t i = (ptrdiff_t)parts.len - 1; i >= 0; i--) {
                acc = regex_builder_mk_union(self, parts.data[i], acc);
            }
            if (parts.data) n00b_free(parts.data);
            out = acc;
        }
        break;
    }
    case KIND_CONCAT: {
        if (fwd && nodeid_is_ts(l) && nodeid_is_lookahead(r, self)
            && nodeid_is_missing(regex_builder_get_lookahead_tail(self, r))
            && regex_builder_get_lookahead_rel(self, r) == 0) {
            NodeId body = regex_builder_get_lookahead_inner(self, r);
            if (regex_builder_is_nullable(self, body, NULLABILITY_END)) {
                out = NODE_ID_TS;
                break;
            }
        }
        NodeId pl = regex_builder_prune_rec(self, l, memo, fwd);
        NodeId pr = regex_builder_prune_rec(self, r, memo, fwd);
        out = regex_builder_mk_concat(self, pl, pr);
        break;
    }
    case KIND_INTER: {
        NodeId pl = regex_builder_prune_rec(self, l, memo, fwd);
        NodeId pr = regex_builder_prune_rec(self, r, memo, fwd);
        out = regex_builder_mk_inter(self, pl, pr);
        break;
    }
    case KIND_COMPL: {
        NodeId pl = regex_builder_prune_rec(self, l, memo, fwd);
        out = regex_builder_mk_compl(self, pl);
        break;
    }
    case KIND_LOOKAHEAD: {
        uint32_t lrel = regex_builder_get_lookahead_rel(self, node_id);
        NodeId body = regex_builder_strip_la_body_end(self, regex_builder_get_lookahead_inner(self, node_id));
        body = regex_builder_prune_rec(self, body, memo, fwd);
        NodeId tail;
        if (nodeid_is_missing(regex_builder_get_lookahead_tail(self, node_id))) {
            tail = NODE_ID_MISSING;
        }
        else {
            tail = regex_builder_prune_rec(self, regex_builder_get_lookahead_tail(self, node_id), memo, fwd);
        }
        out = regex_builder_mk_lookahead_internal(self, body, tail, lrel);
        break;
    }
    case KIND_BEGIN:
        out = NODE_ID_BOT;
        break;
    case KIND_COUNTED: {
        NodeId body = regex_builder_prune_rec(self, l, memo, fwd);
        NodeId chain = regex_builder_prune_rec(self, r, memo, fwd);
        out = regex_builder_mk_counted(self, body, chain, regex_builder_get_extra(self, node_id));
        break;
    }
    case KIND_END:
    case KIND_PRED:
        out = node_id;
        break;
    case KIND_STAR: {
        NodeId pl = regex_builder_prune_rec(self, l, memo, fwd);
        out = regex_builder_mk_star(self, pl);
        break;
    }
    case KIND_LOOKBEHIND: {
        NodeId pl = regex_builder_prune_rec(self, l, memo, fwd);
        if (nodeid_is_missing(r)) out = pl;
        else out = node_id;
        break;
    }
    default:
        out = node_id;
        break;
    }
    nimap_insert(memo, node_id, out);
    return out;
}

NodeId
regex_builder_prune_fwd(RegexBuilder *self, NodeId node_id, NodeIdMap *memo)
{
    return regex_builder_prune_rec(self, node_id, memo, true);
}

NodeId
regex_builder_prune_rev(RegexBuilder *self, NodeId node_id, NodeIdMap *memo)
{
    return regex_builder_prune_rec(self, node_id, memo, false);
}

// ============================================================================
// mk_unions / mk_inters / mk_concats.
// ============================================================================

static NodeId
regex_builder_mk_unions_balanced(RegexBuilder *self, const NodeId *nodes, size_t n)
{
    if (n == 0) return NODE_ID_BOT;
    if (n == 1) return nodes[0];
    size_t mid = n / 2;
    NodeId left  = regex_builder_mk_unions_balanced(self, nodes, mid);
    NodeId right = regex_builder_mk_unions_balanced(self, nodes + mid, n - mid);
    return regex_builder_mk_union(self, left, right);
}

NodeId
regex_builder_mk_unions(RegexBuilder *self, const NodeId *nodes_in, size_t n_in)
{
    n00b_require(self != nullptr, "regex_builder_mk_unions: self must not be null");
    n00b_require(nodes_in != nullptr || n_in == 0,
                 "regex_builder_mk_unions: nodes must not be null when n > 0");
    if (n_in <= 1) return n_in == 0 ? NODE_ID_BOT : nodes_in[0];
    NodeId *sorted = n00b_alloc_array_with_opts(NodeId, n_in, &(n00b_alloc_opts_t){.allocator = self->allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE});
    memcpy(sorted, nodes_in, n_in * sizeof(NodeId));
    qsort(sorted, n_in, sizeof(NodeId), nodeid_cmp);
    size_t w = 0;
    for (size_t i = 0; i < n_in; i++) {
        if (w == 0 || sorted[w - 1].v != sorted[i].v) sorted[w++] = sorted[i];
    }
    size_t w2 = 0;
    for (size_t i = 0; i < w; i++) {
        if (sorted[i].v != NODE_ID_BOT.v) sorted[w2++] = sorted[i];
    }
    if (w2 == 0) { n00b_free(sorted); return NODE_ID_BOT; }

    if (w2 > 16) {
        NodeIdGroupMap *groups = NodeIdGroupMap_new(self->allocator);
        NodeIdHashSet  *heads  = NodeIdHashSet_new(self->allocator);
        size_t ng = 0;
        NodeId *non_concat = n00b_alloc_array_with_opts(NodeId, w2, &(n00b_alloc_opts_t){.allocator = self->allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE});
        size_t nc_len = 0;
        for (size_t i = 0; i < w2; i++) {
            NodeId n = sorted[i];
            if (nodeid_is_concat(n, self)) {
                NodeId h = regex_builder_get_left(self, n);
                NodeId tail = regex_builder_get_right(self, n);
                GroupTails gt;
                if (NodeIdGroupMap_get(groups, h, &gt)) {
                    group_tails_push(&gt, tail, self->allocator);
                    NodeIdGroupMap_insert(groups, h, gt);
                }
                else {
                    GroupTails fresh = (GroupTails){};
                    group_tails_push(&fresh, tail, self->allocator);
                    NodeIdGroupMap_insert(groups, h, fresh);
                    NodeIdHashSet_insert(heads, h);
                    ng += 1;
                }
            }
            else {
                non_concat[nc_len++] = n;
            }
        }
        NodeIdHashSet *absorbed = NodeIdHashSet_new(self->allocator);
        size_t ab_len = 0;
        for (size_t i = 0; i < nc_len; i++) {
            if (NodeIdHashSet_contains(heads, non_concat[i])) {
                if (NodeIdHashSet_insert(absorbed, non_concat[i])) ab_len += 1;
            }
        }
        if (ab_len > 0) {
            size_t kw = 0;
            for (size_t i = 0; i < nc_len; i++) {
                if (!NodeIdHashSet_contains(absorbed, non_concat[i])) {
                    non_concat[kw++] = non_concat[i];
                }
            }
            nc_len = kw;
        }
        if (ng < w2) {
            size_t res_cap = safe_add_sz(nc_len, ng);
            if (res_cap == 0) res_cap = 1;
            NodeId *result = n00b_alloc_array_with_opts(NodeId, res_cap, &(n00b_alloc_opts_t){.allocator = self->allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE});
            size_t result_len = 0;
            for (size_t i = 0; i < nc_len; i++) result[result_len++] = non_concat[i];
            n00b_dict_foreach(groups, head_k, gt, {
                size_t alloc_n = safe_add_sz(gt.len, (size_t)1);
                NodeId *tail_nodes = n00b_alloc_array_with_opts(NodeId, alloc_n, &(n00b_alloc_opts_t){.allocator = self->allocator, .scan_kind = N00B_GC_SCAN_KIND_NONE});
                size_t tn_len = 0;
                for (size_t j = 0; j < gt.len; j++) tail_nodes[tn_len++] = gt.data[j];
                if (NodeIdHashSet_contains(absorbed, head_k)) {
                    tail_nodes[tn_len++] = NODE_ID_EPS;
                }
                NodeId tail_union = regex_builder_mk_unions(self, tail_nodes, tn_len);
                NodeId factored  = regex_builder_mk_concat(self, head_k, tail_union);
                n00b_free(tail_nodes);
                if (result_len == res_cap) {
                    size_t nc = res_cap ? safe_mul_sz(res_cap, 2) : 8;
                    grow_buf(NodeId, self->allocator, &result, &res_cap, result_len, nc);
                }
                result[result_len++] = factored;
            });
            qsort(result, result_len, sizeof(NodeId), nodeid_cmp);
            size_t rw = 0;
            for (size_t i = 0; i < result_len; i++) {
                if (rw == 0 || result[rw - 1].v != result[i].v) result[rw++] = result[i];
            }
            NodeId final_id = regex_builder_mk_unions_balanced(self, result, rw);
            n00b_free(result);
            n00b_dict_foreach(groups, hk, gt2, { (void)hk; if (gt2.data) n00b_free(gt2.data); });
            n00b_free(non_concat);
            n00b_free(sorted);
            return final_id;
        }
        n00b_dict_foreach(groups, hk, gt3, { (void)hk; if (gt3.data) n00b_free(gt3.data); });
        n00b_free(non_concat);
    }
    NodeId result = regex_builder_mk_unions_balanced(self, sorted, w2);
    n00b_free(sorted);
    return result;
}

NodeId
regex_builder_mk_inters(RegexBuilder *self, const NodeId *nodes, size_t n)
{
    n00b_require(self != nullptr, "regex_builder_mk_inters: self must not be null");
    n00b_require(nodes != nullptr || n == 0,
                 "regex_builder_mk_inters: nodes must not be null when n > 0");
    NodeId acc = NODE_ID_TS;
    for (ptrdiff_t i = (ptrdiff_t)n - 1; i >= 0; i--) {
        acc = regex_builder_mk_inter(self, acc, nodes[i]);
    }
    return acc;
}

NodeId
regex_builder_mk_concats(RegexBuilder *self, const NodeId *nodes, size_t n)
{
    n00b_require(self != nullptr, "regex_builder_mk_concats: self must not be null");
    n00b_require(nodes != nullptr || n == 0,
                 "regex_builder_mk_concats: nodes must not be null when n > 0");
    NodeId acc = NODE_ID_EPS;
    for (ptrdiff_t i = (ptrdiff_t)n - 1; i >= 0; i--) {
        acc = regex_builder_mk_concat(self, nodes[i], acc);
    }
    return acc;
}

// ============================================================================
// iter_sat / IterSatStack / extract_sat / iter_unions_b /
// iter_union / iter_inter / iter_union_while.
// ============================================================================

void
iter_sat_stack_init(IterSatStack *s)
{
    *s = (IterSatStack){};
}

void
iter_sat_stack_push(IterSatStack *s, IterSatFrame f, n00b_allocator_t *allocator)
{
    if (s->len == s->cap) {
        size_t nc = s->cap ? safe_mul_sz(s->cap, 2) : 8;
        grow_buf(IterSatFrame, allocator, &s->data, &s->cap, s->len, nc);
    }
    s->data[s->len++] = f;
}

void
iter_sat_stack_free(IterSatStack *s)
{
    if (s->data) n00b_free(s->data);
    *s = (IterSatStack){};
}

void
regex_builder_iter_sat(RegexBuilder *self, IterSatStack *stack,
                       void *ctx, void (*f)(void *, RegexBuilder *, NodeId, TSetId))
{
    while (stack->len > 0) {
        IterSatFrame top = stack->data[--stack->len];
        const TRegex_TSetId *t = regex_builder_get_tregex(self, top.id);
        switch (t->selector) {
        case typehash(TRegex_leaf_t): {
            NodeId n = n00b_variant_get(*t, TRegex_leaf_t).leaf;
            if (!nodeid_eq(n, NODE_ID_BOT)) {
                f(ctx, self, n, top.set);
            }
            break;
        }
        case typehash(TRegex_ite_t): {
            TRegex_ite_t _i  = n00b_variant_get(*t, TRegex_ite_t);
            TSetId   cnd     = _i.set;
            TRegexId then_id = _i.then_id;
            TRegexId else_id = _i.else_id;
            if (else_id.v != TREGEX_ID_BOT.v) {
                TSetId notcnd = solver_not_id(regex_builder_solver(self), cnd);
                TSetId interset1 = solver_and_id(regex_builder_solver(self), top.set, notcnd);
                iter_sat_stack_push(stack, (IterSatFrame){ else_id, interset1 },
                                    self->allocator);
            }
            TSetId interset2 = solver_and_id(regex_builder_solver(self), top.set, cnd);
            iter_sat_stack_push(stack, (IterSatFrame){ then_id, interset2 },
                                self->allocator);
            break;
        }
        }
    }
}

static void
vec_nodeid_pub_push(VecNodeIdPub *v, NodeId n, n00b_allocator_t *allocator)
{
    if (v->len == v->cap) {
        size_t nc = v->cap ? safe_mul_sz(v->cap, 2) : 8;
        grow_buf(NodeId, allocator, &v->data, &v->cap, v->len, nc);
    }
    v->data[v->len++] = n;
}

void
regex_builder_extract_sat(const RegexBuilder *self, TRegexId term_id, VecNodeIdPub *out)
{
    const TRegex_TSetId *t = regex_builder_get_tregex(self, term_id);
    switch (t->selector) {
    case typehash(TRegex_leaf_t): {
        NodeId _leaf = n00b_variant_get(*t, TRegex_leaf_t).leaf;
        if (!nodeid_eq(_leaf, NODE_ID_BOT)) {
            vec_nodeid_pub_push(out, _leaf, self->allocator);
        }
        break;
    }
    case typehash(TRegex_ite_t): {
        TRegex_ite_t _i = n00b_variant_get(*t, TRegex_ite_t);
        regex_builder_extract_sat(self, _i.then_id, out);
        regex_builder_extract_sat(self, _i.else_id, out);
        break;
    }
    }
}

void
regex_builder_iter_unions_b(RegexBuilder *self, NodeId curr, void *ctx,
                            void (*f)(void *, RegexBuilder *, NodeId))
{
    while (regex_builder_get_kind(self, curr) == KIND_UNION) {
        f(ctx, self, nodeid_left(curr, self));
        curr = nodeid_right(curr, self);
    }
    f(ctx, self, curr);
}

void
regex_builder_iter_union(RegexBuilder *self, NodeId u, void *ctx,
                         void (*visit)(void *, RegexBuilder *, NodeId))
{
    n00b_require(self != nullptr, "regex_builder_iter_union: self must not be null");
    n00b_require(visit != nullptr, "regex_builder_iter_union: visit must not be null");
    NodeId curr = u;
    while (regex_builder_get_kind(self, curr) == KIND_UNION) {
        visit(ctx, self, regex_builder_get_left(self, curr));
        curr = regex_builder_get_right(self, curr);
    }
    visit(ctx, self, curr);
}

void
regex_builder_iter_inter(RegexBuilder *self, NodeId head, void *ctx,
                         void (*visit)(void *, RegexBuilder *, NodeId))
{
    n00b_require(self != nullptr, "regex_builder_iter_inter: self must not be null");
    n00b_require(visit != nullptr, "regex_builder_iter_inter: visit must not be null");
    NodeId curr = head;
    while (regex_builder_get_kind(self, curr) == KIND_INTER) {
        visit(ctx, self, regex_builder_get_left(self, curr));
        curr = regex_builder_get_right(self, curr);
    }
    visit(ctx, self, curr);
}

void
regex_builder_iter_union_while(RegexBuilder *self, NodeId rhs,
                               void *visitor_ctx,
                               bool (*visitor)(void *, RegexBuilder *, NodeId))
{
    n00b_require(self != nullptr, "regex_builder_iter_union_while: self must not be null");
    n00b_require(visitor != nullptr, "regex_builder_iter_union_while: visitor must not be null");
    NodeId curr = rhs;
    bool keep_going = true;
    while (keep_going && regex_builder_get_kind(self, curr) == KIND_UNION) {
        keep_going = visitor(visitor_ctx, self, regex_builder_get_left(self, curr));
        curr = regex_builder_get_right(self, curr);
    }
    if (keep_going) {
        visitor(visitor_ctx, self, curr);
    }
}

// ============================================================================
// try_elim_lookarounds / mk_non_nullable_safe.
// ============================================================================

NodeId
regex_builder_try_elim_lookarounds(RegexBuilder *self, NodeId node_id)
{
    n00b_require(self != nullptr, "regex_builder_try_elim_lookarounds: self must not be null");
    n00b_require((size_t)node_id.v < self->array.len,
                 "regex_builder_try_elim_lookarounds: NodeId out of bounds");
    if (!regex_builder_contains_look(self, node_id)) return node_id;
    switch (regex_builder_get_kind(self, node_id)) {
    case KIND_PRED: case KIND_BEGIN: case KIND_END:
        return node_id;
    case KIND_CONCAT: {
        NodeId el = regex_builder_try_elim_lookarounds(self, nodeid_left(node_id, self));
        if (nodeid_eq(el, NODE_ID_MISSING)) return NODE_ID_MISSING;
        NodeId er = regex_builder_try_elim_lookarounds(self, nodeid_right(node_id, self));
        if (nodeid_eq(er, NODE_ID_MISSING)) return NODE_ID_MISSING;
        return regex_builder_mk_concat(self, el, er);
    }
    case KIND_UNION: {
        NodeId el = regex_builder_try_elim_lookarounds(self, nodeid_left(node_id, self));
        if (nodeid_eq(el, NODE_ID_MISSING)) return NODE_ID_MISSING;
        NodeId er = regex_builder_try_elim_lookarounds(self, nodeid_right(node_id, self));
        if (nodeid_eq(er, NODE_ID_MISSING)) return NODE_ID_MISSING;
        return regex_builder_mk_union(self, el, er);
    }
    case KIND_STAR: {
        NodeId el = regex_builder_try_elim_lookarounds(self, nodeid_left(node_id, self));
        if (nodeid_eq(el, NODE_ID_MISSING)) return NODE_ID_MISSING;
        return regex_builder_mk_star(self, el);
    }
    case KIND_COMPL: {
        NodeId el = regex_builder_try_elim_lookarounds(self, nodeid_left(node_id, self));
        if (nodeid_eq(el, NODE_ID_MISSING)) return NODE_ID_MISSING;
        return regex_builder_mk_compl(self, el);
    }
    case KIND_LOOKAHEAD: {
        uint32_t rel = regex_builder_get_lookahead_rel(self, node_id);
        if (rel != 0) return NODE_ID_MISSING;
        NodeId lbody = regex_builder_get_lookahead_inner(self, node_id);
        NodeId ltail = nodeid_missing_to_eps(regex_builder_get_lookahead_tail(self, node_id));
        NodeId el = regex_builder_try_elim_lookarounds(self, lbody);
        if (nodeid_eq(el, NODE_ID_MISSING)) return NODE_ID_MISSING;
        NodeId er = regex_builder_try_elim_lookarounds(self, ltail);
        if (nodeid_eq(er, NODE_ID_MISSING)) return NODE_ID_MISSING;
        NodeId lbody_ts = regex_builder_mk_concat(self, el, NODE_ID_TS);
        NodeId ltail_ts = regex_builder_mk_concat(self, er, NODE_ID_TS);
        return regex_builder_mk_inter(self, lbody_ts, ltail_ts);
    }
    case KIND_LOOKBEHIND: {
        NodeId linner = regex_builder_get_lookbehind_inner(self, node_id);
        NodeId lprev  = nodeid_missing_to_eps(regex_builder_get_lookbehind_prev(self, node_id));
        NodeId el = regex_builder_try_elim_lookarounds(self, linner);
        if (nodeid_eq(el, NODE_ID_MISSING)) return NODE_ID_MISSING;
        NodeId er = regex_builder_try_elim_lookarounds(self, lprev);
        if (nodeid_eq(er, NODE_ID_MISSING)) return NODE_ID_MISSING;
        NodeId lbody_ts = regex_builder_mk_concat(self, NODE_ID_TS, el);
        NodeId ltail_ts = regex_builder_mk_concat(self, NODE_ID_TS, er);
        return regex_builder_mk_inter(self, lbody_ts, ltail_ts);
    }
    case KIND_INTER: {
        NodeId el = regex_builder_try_elim_lookarounds(self, nodeid_left(node_id, self));
        if (nodeid_eq(el, NODE_ID_MISSING)) return NODE_ID_MISSING;
        NodeId er = regex_builder_try_elim_lookarounds(self, nodeid_right(node_id, self));
        if (nodeid_eq(er, NODE_ID_MISSING)) return NODE_ID_MISSING;
        return regex_builder_mk_inter(self, el, er);
    }
    case KIND_COUNTED:
        return NODE_ID_MISSING;
    }
    return NODE_ID_MISSING;
}

NodeId
regex_builder_mk_non_nullable_safe(RegexBuilder *self, NodeId node)
{
    n00b_require(self != nullptr, "regex_builder_mk_non_nullable_safe: self must not be null");
    n00b_require((size_t)node.v < self->array.len,
                 "regex_builder_mk_non_nullable_safe: NodeId out of bounds");
    if (nullability_eq(regex_builder_nullability(self, node), NULLABILITY_NEVER)) return node;
    return regex_builder_mk_inter(self, NODE_ID_TOPPLUS, node);
}

// ============================================================================
// is_empty_lang_internal / is_empty_lang / subsumes_known + helpers.
// ============================================================================

typedef struct TRegexStack {
    TRegexId *data;
    size_t    len;
    size_t    cap;
} TRegexStack;

static void
tregex_stack_push(TRegexStack *s, TRegexId v, n00b_allocator_t *allocator)
{
    if (s->len == s->cap) {
        size_t nc = s->cap ? safe_mul_sz(s->cap, 2) : 8;
        grow_buf(TRegexId, allocator, &s->data, &s->cap, s->len, nc);
    }
    s->data[s->len++] = v;
}

static bool
regex_builder_iter_find_stack(const RegexBuilder *self, TRegexStack *stack,
                              void *ctx, bool (*f)(void *, NodeId))
{
    while (stack->len > 0) {
        TRegexId curr = stack->data[--stack->len];
        const TRegex_TSetId *t = regex_builder_get_tregex(self, curr);
        switch (t->selector) {
        case typehash(TRegex_leaf_t): {
            NodeId n = n00b_variant_get(*t, TRegex_leaf_t).leaf;
            NodeId cur = n;
            while (!nodeid_eq(cur, NODE_ID_BOT)) {
                if (regex_builder_get_kind(self, cur) == KIND_UNION) {
                    if (f(ctx, nodeid_left(cur, self))) return true;
                    cur = nodeid_right(cur, self);
                }
                else {
                    if (f(ctx, n)) return true;
                    cur = NODE_ID_BOT;
                }
            }
            break;
        }
        case typehash(TRegex_ite_t): {
            TRegex_ite_t _i  = n00b_variant_get(*t, TRegex_ite_t);
            TRegexId then_id = _i.then_id;
            TRegexId else_id = _i.else_id;
            if (else_id.v != TREGEX_ID_BOT.v) {
                tregex_stack_push(stack, else_id, self->allocator);
            }
            tregex_stack_push(stack, then_id, self->allocator);
            break;
        }
        }
    }
    return false;
}

// VecDeque<NodeId> approximation backed by `n00b_alloc_array`.  The deque
// owns its (data, head, tail, cap) tuple and frees the buffer in the
// matching teardown.
typedef struct NodeDeque {
    NodeId *data;
    size_t  head, tail;
    size_t  cap;
} NodeDeque;

static void
node_deque_grow(NodeDeque *d)
{
    size_t old_cap = d->cap;
    size_t new_cap = old_cap ? safe_mul_sz(old_cap, 2) : 16;
    NodeId *nb = n00b_alloc_array_with_opts(NodeId, new_cap, &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_NONE});
    size_t k = 0;
    if (old_cap) {
        for (size_t i = d->head; i != d->tail; i = (i + 1) % old_cap) nb[k++] = d->data[i];
    }
    if (d->data) n00b_free(d->data);
    d->data = nb;
    d->cap  = new_cap;
    d->head = 0;
    d->tail = k;
}

static void
deque_push_back(NodeDeque *d, NodeId n)
{
    if (d->cap == 0 || ((d->tail + 1) % d->cap) == d->head) {
        node_deque_grow(d);
    }
    d->data[d->tail] = n;
    d->tail = (d->tail + 1) % d->cap;
}

static void
deque_push_front(NodeDeque *d, NodeId n)
{
    if (d->cap == 0 || ((d->tail + 1) % d->cap) == d->head) {
        node_deque_grow(d);
    }
    d->head = (d->head + d->cap - 1) % d->cap;
    d->data[d->head] = n;
}

static bool
deque_pop_front(NodeDeque *d, NodeId *out)
{
    if (d->head == d->tail) return false;
    *out = d->data[d->head];
    d->head = (d->head + 1) % d->cap;
    return true;
}

static void
node_deque_free(NodeDeque *d)
{
    if (d->data) n00b_free(d->data);
    *d = (NodeDeque){};
}

typedef struct {
    RegexBuilder *self;
    NodeId        initial_node;
    NodeIdMap    *visited;
    NodeDeque    *worklist;
} EmptyLangIter1Ctx;

static bool
empty_lang_iter1(void *ctx_v, NodeId node)
{
    EmptyLangIter1Ctx *ctx = ctx_v;
    nimap_insert(ctx->visited, node, ctx->initial_node);
    Nullability nu = regex_builder_nullability(ctx->self, node);
    if (!nullability_eq(nu, NULLABILITY_NEVER)) return true;
    deque_push_back(ctx->worklist, node);
    return false;
}

typedef struct {
    RegexBuilder *self;
    NodeIdMap    *visited;
    NodeDeque    *worklist;
    NodeId        outer;
    NodeId        found_node;
} EmptyLangIter2Ctx;

static bool
empty_lang_iter2(void *ctx_v, NodeId node)
{
    EmptyLangIter2Ctx *ctx = ctx_v;
    NodeId existing;
    if (nimap_get(ctx->visited, node, &existing)) {
        return false;
    }
    ctx->found_node = node;
    if (!metaflags_contains_inter(regex_builder_get_meta_flags(ctx->self, node))) {
        return true;
    }
    nimap_insert(ctx->visited, node, ctx->outer);
    deque_push_front(ctx->worklist, node);
    return regex_builder_any_nonbegin_nullable(ctx->self, node);
}

static n00b_regex_algebra_err_t
regex_builder_is_empty_lang_internal(RegexBuilder *self, NodeId initial_node, NodeFlags *out_flag)
{
    if (!metaflags_contains_inter(regex_builder_get_meta_flags(self, initial_node))) {
        *out_flag = NODE_FLAGS_ZERO;
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    NodeIdMap visited = (NodeIdMap){.allocator = self->allocator};
    NodeDeque worklist = (NodeDeque){};
    auto begin_der_r = regex_builder_der(self, initial_node, NULLABILITY_BEGIN);
    if (!n00b_result_is_ok(begin_der_r)) {
        node_deque_free(&worklist);
        return (n00b_regex_algebra_err_t)n00b_result_get_err(begin_der_r);
    }
    TRegexId begin_der = n00b_result_get(begin_der_r);
    TRegexStack stack = (TRegexStack){};
    tregex_stack_push(&stack, begin_der, self->allocator);
    EmptyLangIter1Ctx ctx1 = (EmptyLangIter1Ctx){ self, initial_node, &visited, &worklist };
    bool found_null_immediate = regex_builder_iter_find_stack(self, &stack, &ctx1, empty_lang_iter1);
    if (found_null_immediate) {
        node_deque_free(&worklist);
        if (stack.data) n00b_free(stack.data);
        *out_flag = NODE_FLAGS_ZERO;
        return N00B_REGEX_ALGEBRA_ERR_NONE;
    }
    deque_push_back(&worklist, initial_node);
    NodeFlags isempty_flag;
    NodeId cur;
    for (;;) {
        if (!deque_pop_front(&worklist, &cur)) {
            isempty_flag = NODE_FLAGS_IS_EMPTY;
            break;
        }
        NodeFlags cached;
        if (node_flags_map_get(self->cache_empty, cur, &cached) && nodeflags_is_checked(cached)) {
            if (nodeflags_is_empty(cached)) continue;
            node_deque_free(&worklist);
            if (stack.data) n00b_free(stack.data);
            *out_flag = NODE_FLAGS_ZERO;
            return N00B_REGEX_ALGEBRA_ERR_NONE;
        }
        auto der_r = regex_builder_der(self, cur, NULLABILITY_CENTER);
        if (!n00b_result_is_ok(der_r)) {
            node_deque_free(&worklist);
            if (stack.data) n00b_free(stack.data);
            return (n00b_regex_algebra_err_t)n00b_result_get_err(der_r);
        }
        TRegexId derivative = n00b_result_get(der_r);
        tregex_stack_push(&stack, derivative, self->allocator);
        EmptyLangIter2Ctx ctx2 = (EmptyLangIter2Ctx){ self, &visited, &worklist, cur, NODE_ID_BOT };
        bool found_null = regex_builder_iter_find_stack(self, &stack, &ctx2, empty_lang_iter2);
        if (found_null) {
            node_flags_map_insert(self->cache_empty, cur, NODE_FLAGS_IS_CHECKED);
            isempty_flag = NODE_FLAGS_ZERO;
            break;
        }
    }
    NodeFlags merged = (NodeFlags){ (uint8_t)(isempty_flag.v | NODE_FLAGS_IS_CHECKED.v) };
    node_flags_map_insert(self->cache_empty, initial_node, merged);
    node_deque_free(&worklist);
    if (stack.data) n00b_free(stack.data);
    *out_flag = isempty_flag;
    return N00B_REGEX_ALGEBRA_ERR_NONE;
}

bool
regex_builder_is_empty_lang(RegexBuilder *self, NodeId node, bool *out_known, bool *out_empty)
{
    n00b_require(self != nullptr, "regex_builder_is_empty_lang: self must not be null");
    n00b_require(out_known != nullptr, "regex_builder_is_empty_lang: out_known must not be null");
    n00b_require(out_empty != nullptr, "regex_builder_is_empty_lang: out_empty must not be null");
    n00b_require((size_t)node.v < self->array.len,
                 "regex_builder_is_empty_lang: NodeId out of bounds");
    *out_known = false;
    if (nodeid_eq(node, NODE_ID_BOT)) { *out_known = true; *out_empty = true; return true; }
    if (!nullability_eq(regex_builder_nullability(self, node), NULLABILITY_NEVER)) {
        *out_known = true; *out_empty = false; return true;
    }
    NodeFlags cached;
    if (node_flags_map_get(self->cache_empty, node, &cached) && nodeflags_is_checked(cached)) {
        *out_known = true; *out_empty = nodeflags_is_empty(cached); return true;
    }
    NodeId n2;
    if (!regex_builder_contains_look(self, node)) {
        n2 = node;
    }
    else {
        n2 = regex_builder_try_elim_lookarounds(self, node);
        if (nodeid_eq(n2, NODE_ID_MISSING)) return false;
    }
    NodeFlags isempty_flag;
    n00b_regex_algebra_err_t e = regex_builder_is_empty_lang_internal(self, n2, &isempty_flag);
    if (e != N00B_REGEX_ALGEBRA_ERR_NONE) return false;
    *out_known = true;
    *out_empty = (isempty_flag.v == NODE_FLAGS_IS_EMPTY.v);
    return true;
}

static NodeId
regex_builder_subsumes_wrap(RegexBuilder *self, NodeId n)
{
    NodeId tmp = regex_builder_mk_concat(self, n, NODE_ID_TS);
    return regex_builder_mk_concat(self, NODE_ID_TS, tmp);
}

bool
regex_builder_subsumes_known(RegexBuilder *self, NodeId larger_lang, NodeId smaller_lang,
                             bool *out_known, bool *out_subsumes)
{
    n00b_require(self != nullptr, "regex_builder_subsumes_known: self must not be null");
    n00b_require(out_known != nullptr, "regex_builder_subsumes_known: out_known must not be null");
    n00b_require(out_subsumes != nullptr, "regex_builder_subsumes_known: out_subsumes must not be null");
    n00b_require((size_t)larger_lang.v  < self->array.len, "regex_builder_subsumes_known: larger_lang OOB");
    n00b_require((size_t)smaller_lang.v < self->array.len, "regex_builder_subsumes_known: smaller_lang OOB");
    *out_known = false;
    if (nodeid_eq(larger_lang, smaller_lang)) {
        *out_known = true; *out_subsumes = true; return true;
    }
    Nullability nlarge = regex_builder_nullability(self, larger_lang);
    Nullability nsmall = regex_builder_nullability(self, smaller_lang);
    if (!nullability_eq(nullability_and(nullability_not(nlarge), nsmall), NULLABILITY_NEVER)) {
        *out_known = true; *out_subsumes = false; return true;
    }
    if (regex_builder_contains_look(self, smaller_lang) || regex_builder_contains_look(self, larger_lang)) {
        smaller_lang = regex_builder_subsumes_wrap(self, smaller_lang);
        larger_lang  = regex_builder_subsumes_wrap(self, larger_lang);
    }
    NodeId nota = regex_builder_mk_compl(self, larger_lang);
    NodeId diff = regex_builder_mk_inter(self, smaller_lang, nota);
    return regex_builder_is_empty_lang(self, diff, out_known, out_subsumes);
}

// ============================================================================
// regex_builder_free.
// ============================================================================

void
regex_builder_free(RegexBuilder *self)
{
    if (!self) return;
    // The typed dicts and their internal storage are GC-managed; releasing
    // the wrapper allocations is sufficient.  The Vec-shaped buffers are
    // single-owner and freed explicitly here.
    if (self->array.data)         n00b_free(self->array.data);
    if (self->metadata.data)      n00b_free(self->metadata.data);
    if (self->reversed.data)      n00b_free(self->reversed.data);
    if (self->tr_array.data)      n00b_free(self->tr_array.data);
    if (self->tr_der_center.data) n00b_free(self->tr_der_center.data);
    if (self->tr_der_begin.data)  n00b_free(self->tr_der_begin.data);
    if (self->temp_vec.data)      n00b_free(self->temp_vec.data);
    if (self->mb.array.data)      n00b_free(self->mb.array.data);
    if (self->mb.solver) solver_free(self->mb.solver);
    n00b_free(self);
}

// ============================================================================
// nulls table accessors used by engine's null-table dump.
// ============================================================================

size_t
regex_builder_nulls_count(const RegexBuilder *self)
{
    return nulls_array_len(self->mb.nb.array);
}

size_t
regex_builder_nulls_entry_vec(const RegexBuilder *self, uint32_t id, NullState *out, size_t cap)
{
    size_t n = nulls_entry_len(self->mb.nb.array, id);
    if (out != nullptr) {
        size_t k = n < cap ? n : cap;
        for (size_t i = 0; i < k; i++) out[i] = nulls_entry_get(self->mb.nb.array, id, i);
    }
    return n;
}

// ============================================================================
// Cross-crate alias accessors.
// ============================================================================

bool
tset_contains_byte(const TSet *self, uint8_t b)
{
    return TSet_contains_byte(self, b);
}

int
nodeid_cmp(const void *pa, const void *pb)
{
    const NodeId *a = pa;
    const NodeId *b = pb;
    if (a->v < b->v) return -1;
    if (a->v > b->v) return 1;
    return 0;
}

bool
nullability_mask_has_center(Nullability mask)
{
    return (mask.v & NULLABILITY_CENTER.v) != 0;
}

bool
nullability_mask_has_end(Nullability mask)
{
    return (mask.v & NULLABILITY_END.v) != 0;
}

uint32_t
nullstate_rel(NullState ns)
{
    return ns.rel;
}

bool
nullstate_is_mask_nullable(NullState ns, Nullability mask)
{
    return null_state_is_mask_nullable(&ns, mask);
}

void
n00b_regex_algebra_err_free(int *e)
{
    (void)e;
}

// ============================================================================
// Sentinel NodeId externs (paired with `extern const` in algebra.h).
// ============================================================================

const NodeId NODE_ID_MISSING = (NodeId){ .v = 0 };
const NodeId NODE_ID_BOT     = (NodeId){ .v = 1 };
const NodeId NODE_ID_EPS     = (NodeId){ .v = 2 };
const NodeId NODE_ID_TOP     = (NodeId){ .v = 3 };
const NodeId NODE_ID_TS      = (NodeId){ .v = 4 };
const NodeId NODE_ID_TOPPLUS = (NodeId){ .v = 5 };
const NodeId NODE_ID_BEGIN   = (NodeId){ .v = 6 };
const NodeId NODE_ID_END     = (NodeId){ .v = 7 };





