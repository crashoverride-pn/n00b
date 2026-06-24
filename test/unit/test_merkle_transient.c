// test_merkle_transient.c — WP-001 end-to-end.
//
// Exercises the whole chain through the real toolchain: ncc emits an n00b_trmap
// entry for a payload type with a [[n00b::transient]] field (Phase 1), marshal
// zeroes that field in the serialized image (Phase 2), so the Merkle content
// hash ignores it (Phase 3). Two payloads that differ ONLY in the transient
// field must therefore dedup to the same content-addressed node, while a change
// to a non-transient field must produce a different node.
//
// Requires a transient-emitting ncc (merged upstream). With a pre-transient
// ncc the attribute is silently stripped, no n00b_trmap is emitted, the field
// is NOT zeroed, and the dedup CHECK below fails — which is exactly the gate.

#include <stdint.h>

#include "n00b.h"
#include "crypto/merkle.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "util/assert.h"

#define CHECK(e)                                                               \
    do {                                                                       \
        n00b_require((e), "merkle transient e2e: " #e);                        \
    } while (0)

typedef struct mk_tpayload_t {
    int64_t value;
    int     fd [[n00b::transient]]; // non-portable handle: zeroed on marshal
} mk_tpayload_t;

static mk_tpayload_t *
mk_tp(int64_t value, int fd)
{
    mk_tpayload_t *p = n00b_alloc(mk_tpayload_t);
    p->value         = value;
    p->fd            = fd;
    return p;
}

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    n00b_merkle_t *dag = n00b_merkle_new(mk_tpayload_t);

    // Same value, different transient fd -> the fd is zeroed before hashing,
    // so both produce the same content/node hash and dedup to one node.
    n00b_merkle_hash_t h1
        = n00b_result_get(n00b_merkle_add(dag, mk_tpayload_t, mk_tp(10, 3),
                                          nullptr));
    n00b_merkle_hash_t h2
        = n00b_result_get(n00b_merkle_add(dag, mk_tpayload_t, mk_tp(10, 999),
                                          nullptr));
    CHECK(n00b_merkle_hash_eq(&h1, &h2));
    CHECK(n00b_merkle_count(dag) == 1);

    // A change to the NON-transient field still changes the hash.
    n00b_merkle_hash_t h3
        = n00b_result_get(n00b_merkle_add(dag, mk_tpayload_t, mk_tp(20, 3),
                                          nullptr));
    CHECK(!n00b_merkle_hash_eq(&h1, &h3));
    CHECK(n00b_merkle_count(dag) == 2);

    n00b_shutdown();
    return 0;
}
