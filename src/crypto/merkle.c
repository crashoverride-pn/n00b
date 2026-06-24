#define N00B_USE_INTERNAL_API
#include "n00b.h"
#include "crypto/merkle.h"
#include "core/sha256.h"
#include "core/sha512.h"
#include "core/mutex.h"
#include "util/marshal.h"

#include <string.h>

// WP-001 Phase 3 — content-addressed Merkle DAG.
//
// Nodes are stored as flat little-endian-ish records appended to dag->store
// (a n00b_buffer_t); dag->index maps the hex of a node_hash to that record's
// byte offset. content_hash = digest(marshal(payload, base=0)); node_hash =
// digest(alg ++ link_count ++ content_hash ++ ordered child node_hashes).
// All operations serialize on dag->lock.
//
// NOTE (v1): integer fields are stored in host byte order and SHA digest words
// are copied in host order; a single-machine store is self-consistent. Canonical
// little-endian encoding for portable save/load is a Phase-4 refinement.

// Typed view of the type-erased dag->index.
#define MERKLE_IDX(dag) \
    ((n00b_dict_t(n00b_string_t *, uint64_t) *)(dag)->index)

// ── digest ────────────────────────────────────────────────────────────────

static uint8_t
digest_len(n00b_merkle_alg_t alg)
{
    return alg == N00B_MERKLE_SHA512 ? 64 : 32;
}

static n00b_merkle_hash_t
merkle_digest(n00b_merkle_alg_t alg, const void *data, size_t len)
{
    n00b_merkle_hash_t h = {.alg = alg};

    if (alg == N00B_MERKLE_SHA512) {
        n00b_sha512_digest_t d;
        n00b_sha512_hash(data, len, d);
        h.len = 64;
        memcpy(h.bytes, d, 64);
    }
    else {
        n00b_sha256_digest_t d;
        n00b_sha256_hash(data, len, d);
        h.len = 32;
        memcpy(h.bytes, d, 32);
    }
    return h;
}

bool
n00b_merkle_hash_eq(const n00b_merkle_hash_t *a, const n00b_merkle_hash_t *b)
{
    if (a->alg != b->alg || a->len != b->len) {
        return false;
    }
    return memcmp(a->bytes, b->bytes, a->len) == 0;
}

n00b_string_t *
n00b_merkle_hash_hex(const n00b_merkle_hash_t *h)
{
    static const char hx[] = "0123456789abcdef";
    char              tmp[2 * N00B_MERKLE_DIGEST_MAX];

    for (uint8_t i = 0; i < h->len; i++) {
        tmp[2 * i]     = hx[(h->bytes[i] >> 4) & 0xf];
        tmp[2 * i + 1] = hx[h->bytes[i] & 0xf];
    }
    return n00b_string_from_raw(tmp, (int64_t)(2 * h->len));
}

n00b_string_t *
n00b_merkle_err_str(n00b_merkle_err_t e)
{
    switch (e) {
    case N00B_MERKLE_OK:
        return r"ok";
    case N00B_MERKLE_ERR_NOT_FOUND:
        return r"node not found";
    case N00B_MERKLE_ERR_LINK_MISSING:
        return r"link target not in DAG";
    case N00B_MERKLE_ERR_NOT_HASHABLE:
        return r"payload could not be marshaled";
    case N00B_MERKLE_ERR_TYPE_MISMATCH:
        return r"payload type mismatch";
    case N00B_MERKLE_ERR_BAD_RECORD:
        return r"corrupt node record";
    case N00B_MERKLE_ERR_BAD_MANIFEST:
        return r"bad save-blob manifest";
    case N00B_MERKLE_ERR_VERIFY_FAIL:
        return r"node hash verification failed";
    default:
        return r"unknown merkle error";
    }
}

// ── record write helpers (append to a buffer) ──────────────────────────────

static void
put_u8(n00b_buffer_t *b, uint8_t v)
{
    n00b_buffer_append_bytes(b, &v, 1);
}

static void
put_u64(n00b_buffer_t *b, uint64_t v)
{
    n00b_buffer_append_bytes(b, &v, sizeof(v));
}

static void
put_i64(n00b_buffer_t *b, int64_t v)
{
    n00b_buffer_append_bytes(b, &v, sizeof(v));
}

static void
put_hash(n00b_buffer_t *b, const n00b_merkle_hash_t *h)
{
    put_u8(b, (uint8_t)h->alg);
    put_u8(b, h->len);
    n00b_buffer_append_bytes(b, h->bytes, h->len);
}

// Canonical node-hash preimage: alg ++ count ++ content_hash ++ ordered child
// node_hashes. The single source of truth shared by add and load-verify.
static n00b_merkle_hash_t
node_hash_of(n00b_merkle_alg_t         alg,
             const n00b_merkle_hash_t *content,
             const n00b_merkle_hash_t *links,
             uint64_t                  count)
{
    n00b_buffer_t *pre = n00b_buffer_empty();
    put_u8(pre, (uint8_t)alg);
    put_u64(pre, count);
    put_hash(pre, content);
    for (uint64_t i = 0; i < count; i++) {
        put_hash(pre, &links[i]);
    }
    return merkle_digest(alg, pre->data, pre->byte_len);
}

// ── record read cursor ──────────────────────────────────────────────────────

typedef struct {
    const uint8_t *p;
    size_t         len;
    size_t         cur;
    bool           ok;
} rd_t;

static uint8_t
rd_u8(rd_t *r)
{
    if (!r->ok || r->cur + 1 > r->len) {
        r->ok = false;
        return 0;
    }
    return r->p[r->cur++];
}

static uint64_t
rd_u64(rd_t *r)
{
    uint64_t v = 0;
    if (!r->ok || r->cur + sizeof(v) > r->len) {
        r->ok = false;
        return 0;
    }
    memcpy(&v, r->p + r->cur, sizeof(v));
    r->cur += sizeof(v);
    return v;
}

static int64_t
rd_i64(rd_t *r)
{
    int64_t v = 0;
    if (!r->ok || r->cur + sizeof(v) > r->len) {
        r->ok = false;
        return 0;
    }
    memcpy(&v, r->p + r->cur, sizeof(v));
    r->cur += sizeof(v);
    return v;
}

static n00b_merkle_hash_t
rd_hash(rd_t *r)
{
    n00b_merkle_hash_t h = {};
    h.alg                = (n00b_merkle_alg_t)rd_u8(r);
    h.len                = rd_u8(r);
    if (!r->ok || h.len > N00B_MERKLE_DIGEST_MAX
        || r->cur + h.len > r->len) {
        r->ok = false;
        return h;
    }
    memcpy(h.bytes, r->p + r->cur, h.len);
    r->cur += h.len;
    return h;
}

// ── construction ────────────────────────────────────────────────────────────

n00b_merkle_t *
_n00b_merkle_new(uint64_t payload_tid) _kargs
{
    n00b_allocator_t *allocator = nullptr;
    n00b_merkle_alg_t digest    = N00B_MERKLE_SHA256;
}
{
    n00b_merkle_t *dag = n00b_alloc(n00b_merkle_t, .allocator = allocator);

    dag->alg         = digest;
    dag->payload_tid = payload_tid;
    dag->allocator   = allocator;
    dag->store       = n00b_buffer_empty(.allocator = allocator);
    dag->index       = n00b_dict_new(n00b_string_t *, uint64_t,
                                     .allocator = allocator);
    dag->node_count  = 0;
    n00b_sys_mutex_init(&dag->lock, N00B_LOC_STRING());

    return dag;
}

// Caller must hold dag->lock.
static bool
contains_locked(n00b_merkle_t *dag, const n00b_merkle_hash_t *h)
{
    n00b_string_t *key = n00b_merkle_hash_hex(h);
    return n00b_dict_contains(MERKLE_IDX(dag), key);
}

// ── add ─────────────────────────────────────────────────────────────────────

n00b_result_t(n00b_merkle_hash_t)
_n00b_merkle_add(n00b_merkle_t                     *dag,
                 void                              *payload,
                 uint64_t                           payload_tid,
                 n00b_list_t(n00b_merkle_hash_t *) *links,
                 int64_t                            epoch)
{
    if (payload_tid != dag->payload_tid) {
        return n00b_result_err(n00b_merkle_hash_t, N00B_MERKLE_ERR_TYPE_MISMATCH);
    }

    n00b_buffer_t *img = n00b_marshal(payload);
    if (img == nullptr) {
        return n00b_result_err(n00b_merkle_hash_t, N00B_MERKLE_ERR_NOT_HASHABLE);
    }

    n00b_merkle_hash_t content = merkle_digest(dag->alg,
                                               img->data,
                                               img->byte_len);
    uint64_t count = links ? (uint64_t)links->len : 0;

    n00b_mutex_lock(&dag->lock);

    // Collect + validate the ordered link hashes; each must already be in the
    // DAG, so a child's hash precedes its parent's and the graph stays acyclic.
    n00b_merkle_hash_t *larr
        = count ? n00b_alloc_array(n00b_merkle_hash_t, count,
                                   .allocator = dag->allocator)
                : nullptr;
    for (uint64_t i = 0; i < count; i++) {
        n00b_merkle_hash_t *lh = n00b_list_get(*links, i);
        if (lh == nullptr || !contains_locked(dag, lh)) {
            n00b_mutex_unlock(&dag->lock);
            return n00b_result_err(n00b_merkle_hash_t,
                                   N00B_MERKLE_ERR_LINK_MISSING);
        }
        larr[i] = *lh;
    }

    n00b_merkle_hash_t node = node_hash_of(dag->alg, &content, larr, count);
    n00b_string_t     *key  = n00b_merkle_hash_hex(&node);

    // Dedup: identical (payload + links) -> identical node_hash -> no-op.
    if (n00b_dict_contains(MERKLE_IDX(dag), key)) {
        n00b_mutex_unlock(&dag->lock);
        return n00b_result_ok(n00b_merkle_hash_t, node);
    }

    // Build + append the flat record.
    uint64_t       offset = dag->store->byte_len;
    n00b_buffer_t *rec    = n00b_buffer_empty();
    put_hash(rec, &node);
    put_hash(rec, &content);
    put_i64(rec, epoch);
    put_u64(rec, payload_tid);
    put_u64(rec, count);
    for (uint64_t i = 0; i < count; i++) {
        put_hash(rec, &larr[i]);
    }
    put_u64(rec, (uint64_t)img->byte_len);
    n00b_buffer_append_bytes(rec, img->data, img->byte_len);

    uint64_t rec_len = sizeof(uint64_t) + (uint64_t)rec->byte_len;
    put_u64(dag->store, rec_len);
    n00b_buffer_concat(dag->store, rec);

    n00b_dict_put(MERKLE_IDX(dag), key, offset);
    dag->node_count++;

    n00b_mutex_unlock(&dag->lock);
    return n00b_result_ok(n00b_merkle_hash_t, node);
}

// ── parse a stored record into a node (caller holds dag->lock) ──────────────

static n00b_merkle_node_t *
parse_record_at(n00b_merkle_t *dag, uint64_t offset, uint64_t *out_rec_len)
{
    rd_t r = {
        .p   = (const uint8_t *)dag->store->data,
        .len = dag->store->byte_len,
        .cur = offset,
        .ok  = true,
    };

    uint64_t rec_len = rd_u64(&r); // total record length, incl. this prefix
    if (out_rec_len != nullptr) {
        *out_rec_len = rec_len;
    }

    n00b_merkle_node_t *node = n00b_alloc(n00b_merkle_node_t,
                                          .allocator = dag->allocator);
    node->node_hash    = rd_hash(&r);
    node->content_hash = rd_hash(&r);
    node->epoch        = rd_i64(&r);
    node->payload_tid  = rd_u64(&r);
    node->link_count   = rd_u64(&r);

    if (!r.ok || node->link_count > r.len) {
        return nullptr;
    }
    if (node->link_count > 0) {
        node->links = n00b_alloc_array(n00b_merkle_hash_t,
                                       node->link_count,
                                       .allocator = dag->allocator);
        for (uint64_t i = 0; i < node->link_count; i++) {
            node->links[i] = rd_hash(&r);
        }
    }

    uint64_t payload_len = rd_u64(&r);
    if (!r.ok || r.cur + payload_len > r.len) {
        return nullptr;
    }
    node->payload_image = n00b_buffer_from_bytes((char *)(r.p + r.cur),
                                                 (int64_t)payload_len,
                                                 .allocator = dag->allocator);
    return node;
}

// ── lookup ────────────────────────────────────────────────────────────────

n00b_option_t(n00b_merkle_node_t *)
n00b_merkle_get(n00b_merkle_t *dag, n00b_merkle_hash_t *node_hash)
{
    n00b_string_t *key = n00b_merkle_hash_hex(node_hash);

    n00b_mutex_lock(&dag->lock);
    bool     found  = false;
    uint64_t offset = n00b_dict_get(MERKLE_IDX(dag), key, &found);
    n00b_merkle_node_t *node = found ? parse_record_at(dag, offset, nullptr)
                                     : nullptr;
    n00b_mutex_unlock(&dag->lock);

    if (node == nullptr) {
        return n00b_option_none(n00b_merkle_node_t *);
    }
    return n00b_option_set(n00b_merkle_node_t *, node);
}

bool
n00b_merkle_contains(n00b_merkle_t *dag, n00b_merkle_hash_t *node_hash)
{
    n00b_mutex_lock(&dag->lock);
    bool r = contains_locked(dag, node_hash);
    n00b_mutex_unlock(&dag->lock);
    return r;
}

uint64_t
n00b_merkle_count(n00b_merkle_t *dag)
{
    n00b_mutex_lock(&dag->lock);
    uint64_t c = dag->node_count;
    n00b_mutex_unlock(&dag->lock);
    return c;
}

// ── payload ─────────────────────────────────────────────────────────────────

n00b_result_t(void *)
_n00b_merkle_payload(n00b_merkle_t      *dag,
                     n00b_merkle_node_t *node,
                     uint64_t            expected_tid,
                     n00b_arena_t       *target_arena)
{
    (void)dag;
    if (expected_tid != node->payload_tid) {
        return n00b_result_err(void *, N00B_MERKLE_ERR_TYPE_MISMATCH);
    }
    void *obj = n00b_unmarshal_one(node->payload_image,
                                   .target_arena = target_arena);
    if (obj == nullptr) {
        return n00b_result_err(void *, N00B_MERKLE_ERR_BAD_RECORD);
    }
    return n00b_result_ok(void *, obj);
}

// ── persistence (save / load) ───────────────────────────────────────────────
//
// Blob layout: magic(8) ++ version(u32) ++ alg(u8) ++ payload_tid(u64) ++
// node_count(u64) ++ store_len(u64) ++ store bytes (the flat records verbatim).
// The magic is a fixed byte string (endian-independent); integers are host
// order (v1).

static const char N00B_MERKLE_MAGIC[8] = {'n', '0', '0', 'b', 'M', 'K', 'D', 1};
#define N00B_MERKLE_SAVE_VERSION 1u

n00b_buffer_t *
n00b_merkle_save(n00b_merkle_t *dag)
{
    n00b_mutex_lock(&dag->lock);

    n00b_buffer_t *out = n00b_buffer_empty(.allocator = dag->allocator);
    n00b_buffer_append_bytes(out, N00B_MERKLE_MAGIC, sizeof(N00B_MERKLE_MAGIC));
    uint32_t version = N00B_MERKLE_SAVE_VERSION;
    n00b_buffer_append_bytes(out, &version, sizeof(version));
    put_u8(out, (uint8_t)dag->alg);
    put_u64(out, dag->payload_tid);
    put_u64(out, dag->node_count);
    put_u64(out, (uint64_t)dag->store->byte_len);
    n00b_buffer_append_bytes(out, dag->store->data, dag->store->byte_len);

    n00b_mutex_unlock(&dag->lock);
    return out;
}

n00b_result_t(n00b_merkle_t *)
_n00b_merkle_load(n00b_buffer_t    *blob,
                  uint64_t          expected_tid,
                  n00b_allocator_t *allocator)
{
    rd_t r = {
        .p   = (const uint8_t *)blob->data,
        .len = (size_t)blob->byte_len,
        .cur = 0,
        .ok  = true,
    };

    if (r.len < sizeof(N00B_MERKLE_MAGIC)
        || memcmp(r.p, N00B_MERKLE_MAGIC, sizeof(N00B_MERKLE_MAGIC)) != 0) {
        return n00b_result_err(n00b_merkle_t *, N00B_MERKLE_ERR_BAD_MANIFEST);
    }
    r.cur += sizeof(N00B_MERKLE_MAGIC);

    uint32_t version = 0;
    if (r.cur + sizeof(version) > r.len) {
        return n00b_result_err(n00b_merkle_t *, N00B_MERKLE_ERR_BAD_MANIFEST);
    }
    memcpy(&version, r.p + r.cur, sizeof(version));
    r.cur += sizeof(version);
    if (version != N00B_MERKLE_SAVE_VERSION) {
        return n00b_result_err(n00b_merkle_t *, N00B_MERKLE_ERR_BAD_MANIFEST);
    }

    n00b_merkle_alg_t alg         = (n00b_merkle_alg_t)rd_u8(&r);
    uint64_t          payload_tid = rd_u64(&r);
    uint64_t          node_count  = rd_u64(&r);
    uint64_t          store_len   = rd_u64(&r);
    if (!r.ok || r.cur + store_len > r.len) {
        return n00b_result_err(n00b_merkle_t *, N00B_MERKLE_ERR_BAD_MANIFEST);
    }
    if (expected_tid != 0 && expected_tid != payload_tid) {
        return n00b_result_err(n00b_merkle_t *, N00B_MERKLE_ERR_TYPE_MISMATCH);
    }

    n00b_merkle_t *dag = n00b_alloc(n00b_merkle_t, .allocator = allocator);
    dag->alg         = alg;
    dag->payload_tid = payload_tid;
    dag->allocator   = allocator;
    dag->store       = n00b_buffer_from_bytes((char *)(r.p + r.cur),
                                        (int64_t)store_len,
                                        .allocator = allocator);
    dag->index       = n00b_dict_new(n00b_string_t *, uint64_t,
                                     .allocator = allocator);
    dag->node_count  = 0;
    n00b_sys_mutex_init(&dag->lock, N00B_LOC_STRING());

    // Scan every record, recompute + verify both hashes, rebuild the index.
    uint64_t offset = 0;
    uint64_t seen   = 0;
    while (offset < store_len) {
        uint64_t            rec_len = 0;
        n00b_merkle_node_t *node    = parse_record_at(dag, offset, &rec_len);
        if (node == nullptr || rec_len == 0 || offset + rec_len > store_len) {
            return n00b_result_err(n00b_merkle_t *, N00B_MERKLE_ERR_BAD_RECORD);
        }

        n00b_merkle_hash_t content2 = merkle_digest(
            dag->alg,
            node->payload_image->data,
            node->payload_image->byte_len);
        if (!n00b_merkle_hash_eq(&content2, &node->content_hash)) {
            return n00b_result_err(n00b_merkle_t *, N00B_MERKLE_ERR_VERIFY_FAIL);
        }
        n00b_merkle_hash_t node2 = node_hash_of(dag->alg,
                                                &node->content_hash,
                                                node->links,
                                                node->link_count);
        if (!n00b_merkle_hash_eq(&node2, &node->node_hash)) {
            return n00b_result_err(n00b_merkle_t *, N00B_MERKLE_ERR_VERIFY_FAIL);
        }

        n00b_string_t *key = n00b_merkle_hash_hex(&node->node_hash);
        n00b_dict_put(MERKLE_IDX(dag), key, offset);
        seen++;
        offset += rec_len;
    }

    if (seen != node_count) {
        return n00b_result_err(n00b_merkle_t *, N00B_MERKLE_ERR_BAD_MANIFEST);
    }
    dag->node_count = seen;

    return n00b_result_ok(n00b_merkle_t *, dag);
}
