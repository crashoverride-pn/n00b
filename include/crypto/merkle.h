/**
 * @file merkle.h
 * @brief Generic content-addressed Merkle DAG (WP-001).
 *
 * A Merkle DAG stores immutable, content-addressed nodes. Each node pairs a
 * generic @em payload (any marshalable n00b object; one payload type per DAG)
 * with an ordered list of links to child nodes. Identity is by hash:
 *
 *   - @b content_hash = digest of the payload's canonical marshal image
 *     (base-0, with [[n00b::transient]] fields zeroed). The same payload value
 *     always yields the same content hash, so identical sub-objects dedup.
 *   - @b node_hash    = digest of a domain-tagged preimage
 *     `tag ++ count ++ content_hash ++ child node_hashes` (count first, fixed
 *     width). Links bind children by their node_hash, so subtree integrity
 *     rolls up the DAG. Offsets never enter any hash.
 *
 * Adding a node is idempotent on node_hash (dedup). Cycles are impossible:
 * every link must already exist in the DAG, so a child's hash precedes its
 * parent's. The structure carries a mandatory rwlock (no unlocked variant).
 *
 * @note Caller contracts (documented, not enforced): the payload type must
 *       marshal deterministically (no unordered containers, no float -0/NaN
 *       ambiguity) and the chosen digest must be collision-resistant — dedup
 *       trusts the digest.
 */
#pragma once

#include "n00b.h"
#include "core/buffer.h" // n00b_buffer_t (returned by save / taken by load)
#include "adt/result.h"  // n00b_result_t
#include "adt/option.h"  // n00b_option_t
#include "adt/list.h"    // n00b_list_t
#include "adt/dict.h"    // n00b_dict_t

// ── Digest ──────────────────────────────────────────────────────────────

// A 1-byte algorithm tag. Plain uint8_t (not a C23 `enum : uint8_t`) so that
// n00b_merkle_hash_t can be used as a typeid'd generic type argument
// (n00b_result_t(n00b_merkle_hash_t)) — typeid's layout walk rejects a
// fixed-underlying-type enum member.
typedef uint8_t n00b_merkle_alg_t;
#define N00B_MERKLE_SHA256 ((n00b_merkle_alg_t)0) // default
#define N00B_MERKLE_SHA512 ((n00b_merkle_alg_t)1)

#define N00B_MERKLE_DIGEST_MAX 64 // fits SHA-512

// Inline, comparable digest value. `len` active bytes (32 for SHA-256, 64 for
// SHA-512); trailing bytes are zero.
typedef struct {
    n00b_merkle_alg_t alg;
    uint8_t           len;
    uint8_t           bytes[N00B_MERKLE_DIGEST_MAX];
} n00b_merkle_hash_t;

extern bool n00b_merkle_hash_eq(const n00b_merkle_hash_t *a,
                                const n00b_merkle_hash_t *b);
// Lowercase hex of the active digest bytes (no prefix). For logs / dict keys.
extern n00b_string_t *n00b_merkle_hash_hex(const n00b_merkle_hash_t *h);

// ── Errors ──────────────────────────────────────────────────────────────

typedef enum {
    N00B_MERKLE_OK               = 0,
    N00B_MERKLE_ERR_NOT_FOUND    = -1, // no node with that hash
    N00B_MERKLE_ERR_LINK_MISSING = -2, // a supplied link is not in the DAG
    N00B_MERKLE_ERR_NOT_HASHABLE = -3, // payload could not be marshaled
    N00B_MERKLE_ERR_TYPE_MISMATCH= -4, // payload type != the DAG's payload type
    N00B_MERKLE_ERR_BAD_RECORD   = -5, // corrupt stored record
    N00B_MERKLE_ERR_BAD_MANIFEST = -6, // bad magic/version/length on load
    N00B_MERKLE_ERR_VERIFY_FAIL  = -7, // a node's recomputed hash != stored hash
} n00b_merkle_err_t;

extern n00b_string_t *n00b_merkle_err_str(n00b_merkle_err_t e);

// ── Types ───────────────────────────────────────────────────────────────

// The DAG. One payload type per DAG (payload_tid). Append-only node store with
// a hash->offset index; both protected by `lock`.
typedef struct n00b_merkle_t {
    n00b_merkle_alg_t alg;
    uint64_t          payload_tid; // typehash(PayloadT *)
    n00b_mutex_t      lock;        // mandatory; serializes all ops (no unlocked
                                   // variant). rwlock for read-concurrency is a
                                   // future refinement.
    n00b_allocator_t *allocator;
    n00b_buffer_t    *store;       // append-only flat node records
    void             *index;       // dict: node_hash hex -> uint64 offset
    uint64_t          node_count;  // distinct nodes stored
} n00b_merkle_t;

// A decoded node (produced by n00b_merkle_get). Read-only.
typedef struct {
    n00b_merkle_hash_t  node_hash;
    n00b_merkle_hash_t  content_hash;
    int64_t             epoch;     // first-seen stamp; -1 if unset. NOT hashed.
    uint64_t            payload_tid;
    uint64_t            link_count;
    n00b_merkle_hash_t *links;     // [link_count] child node hashes, ordered
    n00b_buffer_t      *payload_image; // canonical marshal image (for unmarshal)
} n00b_merkle_node_t;

// ── Construction ────────────────────────────────────────────────────────

extern n00b_merkle_t *
_n00b_merkle_new(uint64_t payload_tid) _kargs
{
    n00b_allocator_t *allocator = nullptr;
    n00b_merkle_alg_t digest    = N00B_MERKLE_SHA256;
};

/** @brief New DAG for payloads of type @p T. @kw digest @kw allocator */
#define n00b_merkle_new(T, ...) \
    _n00b_merkle_new(typehash(T *) __VA_OPT__(, ) __VA_ARGS__)

// ── Mutation / lookup ─────────────────────────────────────────────────────

// Add a node: marshal `payload`, hash it, combine with the ordered child
// `links` (each must already be in the DAG), dedup on node_hash, and append.
// Returns the node_hash. `links` may be nullptr for a leaf.
// `epoch` is a first-seen stamp (-1 = unset); it is metadata, never hashed.
// (Positional rather than a kwarg: ncc's _kargs transform does not support an
// n00b_result_t(...) generic-struct return type.)
extern n00b_result_t(n00b_merkle_hash_t)
_n00b_merkle_add(n00b_merkle_t                     *dag,
                 void                              *payload,
                 uint64_t                           payload_tid,
                 n00b_list_t(n00b_merkle_hash_t *) *links,
                 int64_t                            epoch);

/** @brief Add a node with payload @p p (type @p T) and ordered @p links. */
#define n00b_merkle_add(dag, T, p, links) \
    _n00b_merkle_add((dag), (p), typehash(T *), (links), -1)

/** @brief Like n00b_merkle_add but with an explicit first-seen @p epoch. */
#define n00b_merkle_add_epoch(dag, T, p, links, epoch) \
    _n00b_merkle_add((dag), (p), typehash(T *), (links), (epoch))

extern n00b_option_t(n00b_merkle_node_t *)
n00b_merkle_get(n00b_merkle_t *dag, n00b_merkle_hash_t *node_hash);

extern bool
n00b_merkle_contains(n00b_merkle_t *dag, n00b_merkle_hash_t *node_hash);

// Number of distinct nodes stored.
extern uint64_t n00b_merkle_count(n00b_merkle_t *dag);

// ── Payload access ────────────────────────────────────────────────────────

extern n00b_result_t(void *)
_n00b_merkle_payload(n00b_merkle_t      *dag,
                     n00b_merkle_node_t *node,
                     uint64_t            expected_tid,
                     n00b_arena_t       *target_arena);

/** @brief Unmarshal a node's payload as @p T *. Returns nullptr on mismatch. */
#define n00b_merkle_payload(T, dag, node)                                  \
    ({                                                                     \
        auto _bl_mr = _n00b_merkle_payload((dag), (node), typehash(T *),   \
                                           nullptr);                       \
        n00b_result_is_ok(_bl_mr) ? (T *)n00b_result_get(_bl_mr)           \
                                  : (T *)nullptr;                          \
    })

/** @brief Like n00b_merkle_payload but unmarshal into @p arena. */
#define n00b_merkle_payload_in(T, dag, node, arena)                        \
    ({                                                                     \
        auto _bl_mr = _n00b_merkle_payload((dag), (node), typehash(T *),   \
                                           (arena));                       \
        n00b_result_is_ok(_bl_mr) ? (T *)n00b_result_get(_bl_mr)           \
                                  : (T *)nullptr;                          \
    })

// ── Persistence (save / load) ───────────────────────────────────────────────

// Serialize the whole DAG to a self-describing, versioned, magic-numbered blob
// (manifest + the flat node store). NOTE (v1): host byte order — a blob is
// portable across processes/builds on the same architecture; canonical
// little-endian encoding is a future refinement.
extern n00b_buffer_t *n00b_merkle_save(n00b_merkle_t *dag);

// Load a blob into a fresh DAG. Validates the manifest, rebuilds the index, and
// RECOMPUTES + checks every node's content_hash and node_hash (rejecting any
// tampered record with N00B_MERKLE_ERR_VERIFY_FAIL); every (offset,length) is
// bounds-checked. Errors if the payload type tag does not match @p expected_tid.
extern n00b_result_t(n00b_merkle_t *)
_n00b_merkle_load(n00b_buffer_t    *blob,
                  uint64_t          expected_tid,
                  n00b_allocator_t *allocator);

/** @brief Load a blob whose payload type is @p T. */
#define n00b_merkle_load(T, blob) \
    _n00b_merkle_load((blob), typehash(T *), nullptr)

/** @brief Like n00b_merkle_load but allocate the DAG from @p alloc. */
#define n00b_merkle_load_in(T, blob, alloc) \
    _n00b_merkle_load((blob), typehash(T *), (alloc))
