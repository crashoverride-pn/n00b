#include "n00b.h"
#include "core/alloc.h"
#include "core/thread.h"
#include "core/runtime.h" // n00b_thread_self() macro dereferences rt->threads[]
#include "core/hash.h"
#include "adt/dict.h"
#include "util/assert.h"
#include "util/panic.h"

#include "internal/regex/nulls.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdckdint.h>
#include <string.h> // memcpy / memmove (D13)

// ---------------------------------------------------------------------------
// Faithful per-file translation of upstream Rust resharp `nulls`, with
// resharp-c's containers replaced by n00b primitives:
//
//   - `Nulls`       : owned sorted vector of NullState (BTreeSet semantics —
//                     sorted iter is observable).  Backing storage is
//                     `n00b_alloc_array` + manual geometric grow.
//   - `NullsArray`  : owned Vec<Nulls *> handle table — same backing as Nulls.
//   - `NullsCache`  : `n00b_dict_t(Nulls *, NullsId)` with a custom key
//                     hash that hashes the *content* (the (mask,rel) pairs).
//   - `CreatedMap`  : `n00b_dict_t(Key, NullsId)` with `skip_obj_hash = true`
//                     so `n00b_hash_raw` over the 12-byte Key is used.
// ---------------------------------------------------------------------------

// ===========================================================================
// Small helpers
// ===========================================================================

[[noreturn]] static inline void nulls_capacity_overflow(void)
{
    n00b_panic("nulls.c: capacity overflow");
}

static inline size_t safe_mul_sz(size_t a, size_t b)
{
    size_t r;
    if (ckd_mul(&r, a, b)) {
        nulls_capacity_overflow();
    }
    return r;
}

// Geometric grow for a `T data[]` with `len`/`cap` book-keeping.  Allocates
// a new buffer at the requested capacity, copies `old_len` elements, frees
// the old buffer.  @p alloc routes through a caller-supplied allocator
// (typically the per-regex pool from gc-bits.md Step 5); pass nullptr to
// use the runtime default.
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
// NullState
// ===========================================================================

NullState null_state_new(Nullability mask, uint32_t rel)
{
    return (NullState){.mask = mask, .rel = rel};
}

NullState null_state_new0(Nullability mask)
{
    return (NullState){.mask = mask, .rel = 0};
}

bool null_state_eq(const NullState *a, const NullState *b)
{
    return nullability_eq(a->mask, b->mask) && a->rel == b->rel;
}

bool null_state_is_center_nullable(const NullState *self)
{
    return !nullability_eq(nullability_and(self->mask, NULLABILITY_CENTER),
                           NULLABILITY_NEVER);
}

bool null_state_is_mask_nullable(const NullState *self, Nullability mask)
{
    return !nullability_eq(nullability_and(self->mask, mask), NULLABILITY_NEVER);
}

// Rust impl Ord for NullState:
//   other.rel.cmp(&self.rel).then_with(|| self.mask.cmp(&other.mask))
// Higher rel sorts first; on ties, lower mask sorts first.
int null_state_cmp(const NullState *a, const NullState *b)
{
    if (b->rel < a->rel) return -1;
    if (b->rel > a->rel) return 1;
    return nullability_cmp(a->mask, b->mask);
}

// Enforced invariant: null_state_cmp(a,b) == 0  iff
//   a.mask == b.mask && a.rel == b.rel.
// The dedup simplification in `nulls_builder_or_id` is sound only while
// this property holds.  Called once from `nulls_builder_new` so the check
// sits on a known cold path; runs in release too because the consequence
// of a regression is silent data loss, not a crash.
static void null_state_cmp_invariant_check(void)
{
    static const NullState samples[] = {
        {.mask = {0b000}, .rel = 0},
        {.mask = {0b001}, .rel = 0},
        {.mask = {0b010}, .rel = 0},
        {.mask = {0b100}, .rel = 0},
        {.mask = {0b111}, .rel = 0},
        {.mask = {0b001}, .rel = 1},
        {.mask = {0b001}, .rel = 7},
        {.mask = {0b111}, .rel = 7},
        {.mask = {0b010}, .rel = 42},
    };
    const size_t n = sizeof(samples) / sizeof(samples[0]);
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            const int  c      = null_state_cmp(&samples[i], &samples[j]);
            const bool key_eq = nullability_eq(samples[i].mask, samples[j].mask)
                             && samples[i].rel == samples[j].rel;
            n00b_require((c == 0) == key_eq,
                         "null_state_cmp invariant violated: cmp==0 must "
                         "iff (mask,rel) match");
        }
    }
}

// ===========================================================================
// Nulls — sorted set of NullState
// ===========================================================================

struct Nulls {
    NullState        *data;
    size_t            len;
    size_t            cap;
    /* Per-Nulls allocator forwarded from NullsBuilder so growth /
     * cloning routes through the per-regex pool when in use. */
    n00b_allocator_t *allocator;
};

Nulls *nulls_new_alloc(n00b_allocator_t *allocator)
{
    Nulls *n = n00b_alloc_with_opts(
        Nulls, &(n00b_alloc_opts_t){.allocator = allocator});
    n->allocator = allocator;
    return n;
}

Nulls *nulls_new(void)
{
    return nulls_new_alloc(nullptr);
}

Nulls *nulls_clone(const Nulls *src)
{
    Nulls *n = nulls_new_alloc(src->allocator);
    if (src->len == 0) return n;
    n->data = n00b_alloc_array_with_opts(NullState, src->len,
        &(n00b_alloc_opts_t){
            .allocator = src->allocator,
            .scan_kind = N00B_GC_SCAN_KIND_NONE,
        });
    n->len  = n->cap = src->len;
    memcpy(n->data, src->data, safe_mul_sz(src->len, sizeof(NullState)));
    return n;
}

void nulls_free(Nulls *self)
{
    if (!self) return;
    if (self->data) n00b_free(self->data);
    n00b_free(self);
}

size_t nulls_len(const Nulls *self) { return self->len; }

// Binary search for insertion position; insert if not present (sorted unique).
void nulls_insert(Nulls *self, NullState s)
{
    size_t lo = 0;
    size_t hi = self->len;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int    c   = null_state_cmp(&self->data[mid], &s);
        if (c == 0) return; // already present
        if (c < 0) {
            lo = mid + 1;
        }
        else {
            hi = mid;
        }
    }
    if (self->len == self->cap) {
        size_t nc = self->cap == 0 ? 4 : safe_mul_sz(self->cap, 2);
        grow_buf(NullState, self->allocator, &self->data, self->cap, self->len, nc);
    }
    if (lo < self->len) {
        memmove(&self->data[lo + 1],
                &self->data[lo],
                safe_mul_sz(self->len - lo, sizeof(NullState)));
    }
    self->data[lo] = s;
    self->len += 1;
}

bool nulls_eq(const Nulls *a, const Nulls *b)
{
    if (a->len != b->len) return false;
    for (size_t i = 0; i < a->len; i++) {
        if (!null_state_eq(&a->data[i], &b->data[i])) return false;
    }
    return true;
}

// FNV-1a hash over the (mask, rel) pairs.
uint64_t nulls_hash(const Nulls *self)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < self->len; i++) {
        uint64_t v = ((uint64_t)self->data[i].mask.v << 32)
                   | (uint64_t)self->data[i].rel;
        h ^= v;
        h *= 0x100000001b3ULL;
    }
    return h;
}

void nulls_for_each(const Nulls *self,
                    void (*cb)(const NullState *, void *), void *ctx)
{
    for (size_t i = 0; i < self->len; i++) cb(&self->data[i], ctx);
}

void nulls_for_each_rev(const Nulls *self,
                        void (*cb)(const NullState *, void *), void *ctx)
{
    for (size_t i = self->len; i-- > 0;) cb(&self->data[i], ctx);
}

Nulls *nulls_union(const Nulls *a, const Nulls *b)
{
    Nulls *out = nulls_clone(a);
    for (size_t i = 0; i < b->len; i++) nulls_insert(out, b->data[i]);
    return out;
}

const NullState *nulls_set_get(const Nulls *self, size_t i)
{
    return i < self->len ? &self->data[i] : nullptr;
}
size_t nulls_set_len(const Nulls *self) { return self->len; }

// ===========================================================================
// NullsArray — owned Vec<Nulls *>
// ===========================================================================

struct NullsArray {
    Nulls           **data;
    size_t            len;
    size_t            cap;
    n00b_allocator_t *allocator;
};

NullsArray *nulls_array_new_alloc(n00b_allocator_t *allocator)
{
    NullsArray *a = n00b_alloc_with_opts(
        NullsArray, &(n00b_alloc_opts_t){.allocator = allocator});
    a->allocator = allocator;
    return a;
}

NullsArray *nulls_array_new(void)
{
    return nulls_array_new_alloc(nullptr);
}

void nulls_array_free(NullsArray *a)
{
    if (!a) return;
    for (size_t i = 0; i < a->len; i++) nulls_free(a->data[i]);
    if (a->data) n00b_free(a->data);
    n00b_free(a);
}

void nulls_array_push(NullsArray *a, Nulls *set)
{
    if (a->len == a->cap) {
        size_t nc = a->cap == 0 ? 8 : safe_mul_sz(a->cap, 2);
        grow_buf(Nulls *, a->allocator, &a->data, a->cap, a->len, nc);
    }
    a->data[a->len++] = set;
}

Nulls *nulls_array_get(const NullsArray *a, size_t index)
{
    return index < a->len ? a->data[index] : nullptr;
}

size_t nulls_array_len(const NullsArray *a) { return a->len; }

size_t nulls_entry_len(const NullsArray *a, uint32_t id)
{
    Nulls *s = nulls_array_get(a, (size_t)id);
    return s ? s->len : 0;
}

NullState nulls_entry_get(const NullsArray *a, uint32_t id, size_t idx)
{
    Nulls *s = nulls_array_get(a, (size_t)id);
    return (s && idx < s->len) ? s->data[idx] : (NullState){};
}

// ===========================================================================
// NullsCache — n00b_dict_t(Nulls *, NullsId) with content-based key hash.
// The dict's equality is purely 128-bit hash equality, so the hash function
// must fully discriminate cache keys.  We use n00b_hash_raw over a serialised
// (mask,rel) sequence — the FNV-1a in `nulls_hash` is too narrow (64-bit),
// but `n00b_hash_raw` on the same byte sequence is 128-bit and ample.
// ===========================================================================

// Hash callback for n00b_dict_t.  With `skip_obj_hash = false` and a custom
// `fn`, the dict invokes `fn(*(void **)key)` — i.e. it dereferences the
// stored Nulls* slot and passes the Nulls pointer to us.
static n00b_hash_value_t nulls_ptr_hash(void *opaque)
{
    const Nulls *s = (const Nulls *)opaque;
    if (!s || s->len == 0) {
        return n00b_hash_raw("", 0);
    }
    // (mask:1, _pad:3, rel:4) per element — pad bytes are deterministic
    // because `data` came from `n00b_alloc_array(NullState, ...)` which
    // zero-fills, and assignments only touch the named fields.
    return n00b_hash_raw(s->data, safe_mul_sz(s->len, sizeof(NullState)));
}

struct NullsCache {
    n00b_dict_t(Nulls *, NullsId) *m;
};

NullsCache *nulls_cache_new_alloc(n00b_allocator_t *allocator)
{
    NullsCache *c = n00b_alloc_with_opts(
        NullsCache, &(n00b_alloc_opts_t){.allocator = allocator});
    c->m = n00b_alloc_with_opts(
        n00b_dict_t(Nulls *, NullsId),
        &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(c->m,
                   .hash          = nulls_ptr_hash,
                   .skip_obj_hash = false,
                   .allocator     = allocator);
    return c;
}

NullsCache *nulls_cache_new(void)
{
    return nulls_cache_new_alloc(nullptr);
}

void nulls_cache_free(NullsCache *c)
{
    if (!c) return;
    // The dict itself is GC-managed; per `dict.h` there is no explicit free.
    // The keys stored inside (Nulls *) are owned by NullsArray, not by the
    // cache.  Drop our wrapper.
    n00b_free(c);
}

void nulls_cache_insert(NullsCache *c, const Nulls *key, NullsId id)
{
    // n00b_dict_put expects an lvalue key; cast away const to match the
    // declared `Nulls *` slot type.
    Nulls *k = (Nulls *)key;
    n00b_dict_put(c->m, k, id);
}

bool nulls_cache_get(const NullsCache *c, const Nulls *key, NullsId *out)
{
    bool   found;
    Nulls *k    = (Nulls *)key;
    NullsId got = n00b_dict_get(c->m, k, &found);
    if (found) *out = got;
    return found;
}

size_t nulls_cache_len(const NullsCache *c)
{
    return (size_t)n00b_dict_internal_len((_n00b_dict_internal_t *)c->m);
}

// ===========================================================================
// CreatedMap — n00b_dict_t(Key, NullsId) keyed by raw 12-byte struct.
// `Key` has `static_assert(sizeof(Key) == 12)` and no implicit padding,
// so `skip_obj_hash = true` (no `fn`) yields `n00b_hash_raw(&key, 12)` —
// exactly what we want for content-equality.
// ===========================================================================

struct CreatedMap {
    n00b_dict_t(Key, NullsId) *m;
};

CreatedMap *created_map_new_alloc(n00b_allocator_t *allocator)
{
    CreatedMap *c = n00b_alloc_with_opts(
        CreatedMap, &(n00b_alloc_opts_t){.allocator = allocator});
    c->m = n00b_alloc_with_opts(
        n00b_dict_t(Key, NullsId),
        &(n00b_alloc_opts_t){.allocator = allocator});
    n00b_dict_init(c->m,
                   .skip_obj_hash = true,
                   .allocator     = allocator);
    return c;
}

CreatedMap *created_map_new(void)
{
    return created_map_new_alloc(nullptr);
}

void created_map_free(CreatedMap *c)
{
    if (!c) return;
    n00b_free(c);
}

void created_map_insert(CreatedMap *c, Key key, NullsId id)
{
    n00b_dict_put(c->m, key, id);
}

const NullsId *created_map_get(const CreatedMap *c, const Key *key)
{
    // The contract on this function is "borrowed pointer, valid until next
    // get/insert".  The single-slot scratchpad is folded out of a
    // thread_local into n00b_thread_t::regex_nulls_last (D-012), reached
    // via n00b_thread_self() so a raw worker thread needs zero TLS.  The
    // field is NullsId-shaped (both are a single uint32_t), so it backs
    // the borrowed-pointer return directly.  Before the runtime / calling
    // thread is registered, self() is nullptr; the lookup still works but
    // uses a process-lifetime scratch slot (startup-window guard, matching
    // src/core/data_lock.c) — acceptable because the regex subsystem runs
    // only after the runtime is up.
    n00b_thread_t *self = n00b_thread_self();
    bool           found;
    Key            k = *key;

    if (self == nullptr) {
        static NullsId bootstrap_scratch;
        bootstrap_scratch = n00b_dict_get(c->m, k, &found);
        return found ? &bootstrap_scratch : nullptr;
    }

    NullsId *slot = (NullsId *)&self->regex_nulls_last;
    *slot         = n00b_dict_get(c->m, k, &found);
    return found ? slot : nullptr;
}

// ===========================================================================
// NullsBuilder
// ===========================================================================

// Forward-declared private helpers mirroring the Rust `init` / `init1`.
static NullsId       nulls_builder_init(NullsBuilder *self, Nulls *inst);
static NullsId       nulls_builder_init1(NullsBuilder *self, NullState inst);
static const NullsId *nulls_builder_is_created(const NullsBuilder *self,
                                               const Key *inst);
// File-local: takes ownership of `inst` (consumes on cache hit).  Demoted
// from public API in nulls.h to remove the move-semantics footgun.
static NullsId       nulls_builder_get_id(NullsBuilder *self, Nulls *inst);

NullsBuilder nulls_builder_default(void)
{
    return nulls_builder_new(nullptr);
}

NullsBuilder nulls_builder_new(n00b_allocator_t *allocator)
{
    null_state_cmp_invariant_check();

    NullsBuilder inst = {
        .cache     = nulls_cache_new_alloc(allocator),
        .created   = created_map_new_alloc(allocator),
        .array     = nulls_array_new_alloc(allocator),
        .allocator = allocator,
    };

    Nulls *empty = nulls_new_alloc(allocator);
    (void)nulls_builder_init(&inst, empty);

    NullsId center = nulls_builder_init1(&inst, null_state_new0(NULLABILITY_CENTER));
    NullsId always = nulls_builder_init1(&inst, null_state_new0(NULLABILITY_ALWAYS));
    NullsId begin  = nulls_builder_init1(&inst, null_state_new0(NULLABILITY_BEGIN));
    NullsId end    = nulls_builder_init1(&inst, null_state_new0(NULLABILITY_END));

    // Sentinel-id invariants — the whole port relies on these specific id
    // values matching NULLS_ID_* constants, so a mismatch here is a fatal
    // programming error in any build.
    n00b_require(nulls_id_eq(center, NULLS_ID_CENTER0),
                 "nulls_builder_new: center sentinel id mismatch");
    n00b_require(nulls_id_eq(always, NULLS_ID_ALWAYS0),
                 "nulls_builder_new: always sentinel id mismatch");
    n00b_require(nulls_id_eq(begin, NULLS_ID_BEGIN0),
                 "nulls_builder_new: begin sentinel id mismatch");
    n00b_require(nulls_id_eq(end, NULLS_ID_END0),
                 "nulls_builder_new: end sentinel id mismatch");

    return inst;
}

void nulls_builder_drop(NullsBuilder *self)
{
    if (self == nullptr) return;
    nulls_cache_free(self->cache);
    created_map_free(self->created);
    nulls_array_free(self->array);
    self->cache   = nullptr;
    self->created = nullptr;
    self->array   = nullptr;
}

static NullsId nulls_builder_init(NullsBuilder *self, Nulls *inst)
{
    NullsId new_id = {(uint32_t)nulls_cache_len(self->cache)};
    // Rust does `self.cache.insert(inst.clone(), new_id);
    //            self.array.push(inst);`
    // We clone for the cache key, push the original into the array.
    Nulls *key_clone = nulls_clone(inst);
    nulls_cache_insert(self->cache, key_clone, new_id);
    nulls_array_push(self->array, inst);
    return new_id;
}

static NullsId nulls_builder_init1(NullsBuilder *self, NullState inst)
{
    Nulls *b = nulls_new_alloc(self->allocator);
    nulls_insert(b, inst);
    NullsId new_id    = {(uint32_t)nulls_cache_len(self->cache)};
    Nulls  *key_clone = nulls_clone(b);
    nulls_cache_insert(self->cache, key_clone, new_id);
    nulls_array_push(self->array, b);
    return new_id;
}

const Nulls *nulls_builder_get_set_ref(const NullsBuilder *self, NullsId set_id)
{
    return nulls_array_get(self->array, (size_t)set_id.v);
}

// File-local: this function has move semantics on `inst` — on a cache hit
// it frees `inst` and returns the existing id; on a miss it transfers
// ownership of `inst` into the builder via `nulls_builder_init`.  Callers
// MUST NOT use `inst` after this call returns.
static NullsId nulls_builder_get_id(NullsBuilder *self, Nulls *inst)
{
    NullsId existing;
    if (nulls_cache_get(self->cache, inst, &existing)) {
        nulls_free(inst);
        return existing;
    }
    return nulls_builder_init(self, inst);
}

static const NullsId *nulls_builder_is_created(const NullsBuilder *self,
                                               const Key *inst)
{
    return created_map_get(self->created, inst);
}

// ===========================================================================
// or_id / and_id / and_mask / not_id / add_rel
// ===========================================================================

// Helper context for the `or_id` reverse iteration and dedup.
typedef struct {
    Nulls *result; // output set
    // Track inserted (mask,rel) pairs to mimic Rust's
    //   `result.iter().find(|v| v.mask == m.mask && v.rel == m.rel)`
    // We piggy-back on the destination set: since the sorted-set inserts
    // dedupe by Ord, an exact duplicate already collapses.
    //
    // CORRECTNESS PRECONDITION: this only matches Rust's semantics while
    //   null_state_cmp(a,b) == 0  iff  a.mask == b.mask && a.rel == b.rel.
    // That property is enforced at builder construction time by
    // `null_state_cmp_invariant_check()`.
} OrIterCtx;

static void or_iter_cb(const NullState *m, void *ctx_)
{
    OrIterCtx *ctx = (OrIterCtx *)ctx_;
    nulls_insert(ctx->result, *m);
}

NullsId nulls_builder_or_id(NullsBuilder *self, NullsId set1, NullsId set2)
{
    if (nulls_id_gt(set1, set2)) {
        return nulls_builder_or_id(self, set2, set1);
    }
    Key            key    = {.op = OPERATION_OR, .left = set1, .right = set2};
    const NullsId *cached = nulls_builder_is_created(self, &key);
    if (cached != nullptr) {
        return *cached;
    }
    if (nulls_id_eq(set1, set2)) {
        return set1;
    }
    if (nulls_id_eq(set1, NULLS_ID_ALWAYS0) && nulls_id_eq(set2, NULLS_ID_END0)) {
        return NULLS_ID_ALWAYS0;
    }
    if (nulls_id_eq(set1, NULLS_ID_END0) && nulls_id_eq(set2, NULLS_ID_ALWAYS0)) {
        return NULLS_ID_ALWAYS0;
    }

    const Nulls *a   = nulls_builder_get_set_ref(self, set1);
    const Nulls *b   = nulls_builder_get_set_ref(self, set2);
    Nulls       *all = nulls_union(a, b);

    Nulls *result = nulls_new_alloc(self->allocator);
    OrIterCtx ctx    = {.result = result};
    nulls_for_each_rev(all, or_iter_cb, &ctx);
    nulls_free(all);

    NullsId new_id = nulls_builder_get_id(self, result);
    created_map_insert(self->created, key, new_id);
    return new_id;
}

NullsId nulls_builder_and_id(NullsBuilder *self, NullsId set1, NullsId set2)
{
    if (nulls_id_eq(NULLS_ID_EMPTY, set1)) {
        return NULLS_ID_EMPTY;
    }
    if (nulls_id_eq(NULLS_ID_EMPTY, set2)) {
        return NULLS_ID_EMPTY;
    }
    if (nulls_id_gt(set1, set2)) {
        return nulls_builder_and_id(self, set2, set1);
    }
    Key            key    = {.op = OPERATION_INTER, .left = set1, .right = set2};
    const NullsId *cached = nulls_builder_is_created(self, &key);
    if (cached != nullptr) {
        return *cached;
    }
    if (nulls_id_eq(set1, set2)) {
        return set1;
    }
    if (nulls_id_eq(set1, NULLS_ID_ALWAYS0) && nulls_id_eq(set2, NULLS_ID_END0)) {
        return NULLS_ID_END0;
    }
    if (nulls_id_eq(set1, NULLS_ID_END0) && nulls_id_eq(set2, NULLS_ID_ALWAYS0)) {
        return NULLS_ID_END0;
    }

    // The upstream uses `|` (union) here despite the function being named
    // `and_id` and the operation being OPERATION_INTER.  Faithfully mirrored.
    const Nulls *a        = nulls_builder_get_set_ref(self, set1);
    const Nulls *b        = nulls_builder_get_set_ref(self, set2);
    Nulls       *combined = nulls_union(a, b);
    NullsId      result   = nulls_builder_get_id(self, combined);

    created_map_insert(self->created, key, result);
    return result;
}

// Context for and_mask filter-map.
typedef struct {
    Nullability mask;
    Nulls      *out;
} AndMaskCtx;

static void and_mask_cb(const NullState *v, void *ctx_)
{
    AndMaskCtx *ctx     = (AndMaskCtx *)ctx_;
    Nullability newmask = nullability_and(v->mask, ctx->mask);
    if (nullability_eq(newmask, NULLABILITY_NEVER)) {
        return;
    }
    nulls_insert(ctx->out, null_state_new(newmask, v->rel));
}

NullsId nulls_builder_and_mask(NullsBuilder *self, NullsId set1, Nullability mask)
{
    if (nulls_id_eq(NULLS_ID_EMPTY, set1)
        || nullability_eq(mask, NULLABILITY_NEVER)) {
        return NULLS_ID_EMPTY;
    }
    if (nullability_eq(mask, NULLABILITY_ALWAYS)) {
        return set1;
    }

    const Nulls *src       = nulls_builder_get_set_ref(self, set1);
    Nulls *remaining = nulls_new_alloc(self->allocator);
    AndMaskCtx   ctx       = {.mask = mask, .out = remaining};
    nulls_for_each(src, and_mask_cb, &ctx);

    return nulls_builder_get_id(self, remaining);
}

NullsId nulls_builder_not_id(NullsBuilder *self, NullsId set_id)
{
    if (nulls_id_eq(set_id, NULLS_ID_EMPTY)) {
        return NULLS_ID_ALWAYS0;
    }
    if (nulls_id_eq(set_id, NULLS_ID_ALWAYS0)) {
        return NULLS_ID_EMPTY;
    }
    if (nulls_id_eq(set_id, NULLS_ID_BEGIN0)) {
        return nulls_builder_or_id(self, NULLS_ID_CENTER0, NULLS_ID_END0);
    }
    if (nulls_id_eq(set_id, NULLS_ID_END0)) {
        return nulls_builder_or_id(self, NULLS_ID_CENTER0, NULLS_ID_BEGIN0);
    }
    return NULLS_ID_EMPTY;
}

// Context for add_rel map.
typedef struct {
    uint32_t rel;
    Nulls   *out;
} AddRelCtx;

static void add_rel_cb(const NullState *v, void *ctx_)
{
    AddRelCtx *ctx = (AddRelCtx *)ctx_;
    // Rust uses plain `v.rel + rel` on u32 and would panic on overflow in
    // debug.  We match the unchecked semantics; wrap is the C default.
    nulls_insert(ctx->out, null_state_new(v->mask, v->rel + ctx->rel));
}

NullsId nulls_builder_add_rel(NullsBuilder *self, NullsId set_id, uint32_t rel)
{
    if (rel == 0u || rel == UINT32_MAX) {
        return set_id;
    }
    const Nulls *src_ref = nulls_builder_get_set_ref(self, set_id);
    Nulls       *res     = nulls_clone(src_ref);

    Nulls *with_rel = nulls_new_alloc(self->allocator);
    AddRelCtx ctx      = {.rel = rel, .out = with_rel};
    nulls_for_each(res, add_rel_cb, &ctx);
    nulls_free(res);

    return nulls_builder_get_id(self, with_rel);
}

// ===========================================================================
// Sentinel id definitions and snake_case aliases.
// ===========================================================================

const NullsId NULLS_ID_EMPTY   = {.v = 0};
const NullsId NULLS_ID_CENTER0 = {.v = 1};
const NullsId NULLS_ID_ALWAYS0 = {.v = 2};
const NullsId NULLS_ID_BEGIN0  = {.v = 3};
const NullsId NULLS_ID_END0    = {.v = 4};

// camelCase aliases for engine.c.
const NullsId NullsId_EMPTY   = {.v = 0};
const NullsId NullsId_CENTER0 = {.v = 1};
const NullsId NullsId_ALWAYS0 = {.v = 2};
const NullsId NullsId_BEGIN0  = {.v = 3};
const NullsId NullsId_END0    = {.v = 4};

// Alias for `nulls_insert` used by parser/lib.c.
void null_state_set_insert(Nulls *set, NullState s)
{
    nulls_insert(set, s);
}

// Singleton-set constructor — keeps `nulls_builder_get_id` private.
NullsId nulls_builder_get_id_singleton(NullsBuilder *self, NullState s)
{
    Nulls *single = nulls_new_alloc(self->allocator);
    nulls_insert(single, s);
    return nulls_builder_get_id(self, single);
}
