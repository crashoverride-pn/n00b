/* test/unit/test_marshal_scratch_bound.c - n00b-lang/n00b#432.
 *
 * The marshaler works out of a private scratch pool.  It used to hold, for the
 * whole marshal, one scratch block per marshaled ALLOCATION (`node->payload`,
 * a private copy of the object) plus every superseded half of the output
 * buffer's doubling.  Scratch therefore scaled as a multiple of the image and
 * nothing was reclaimed until the context was destroyed.
 *
 * On Linux/macOS those pages are lazily mapped and the cost is nearly
 * invisible.  On Windows every one of them is VirtualAlloc(MEM_COMMIT) charge:
 * a rocs seal of one ~150 MB hot shard moved ~32 GB of commit, every 300 s
 * checkpoint, for the life of the process.
 *
 * What is asserted here is the PROPERTY, not the implementation: the scratch
 * pool's high-water mark stays within a small multiple of the image it
 * produced.  Pre-fix this graph peaks at well over 3x the image; the bound
 * below is loose enough to survive allocator tuning and tight enough that
 * reintroducing per-object retention fails it.
 */

#include <stdint.h>
#include <string.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/buffer.h"
#include "core/runtime.h"
#include "conduit/print.h"
#include "util/assert.h"
#include "util/marshal.h"

#define CHECK(expr) n00b_require((expr), "test check failed: " #expr)

// Enough distinct large objects that per-object scratch retention dominates
// anything constant: 64 x 256 KB = 16 MB of payload in 64 separate
// allocations, each far past the pool's size-class range, so each one is its
// own mapping.
#define N_OBJECTS   64
#define OBJECT_SIZE (256 * 1024)

// The measured budget.  The marshaler needs the output buffer itself (1x)
// plus its growth transient plus the metadata section, so ~2.2x is the honest
// steady-state cost of building a contiguous image.  Per-object retention
// adds a whole extra copy of the graph on top of that.
#define SCRATCH_BUDGET_NUMERATOR   13
#define SCRATCH_BUDGET_DENOMINATOR 5

typedef struct big_node_t {
    struct big_node_t *next;
    uint64_t           seq;
    char               data[OBJECT_SIZE];
} big_node_t;

static big_node_t *
build_chain(void)
{
    big_node_t *head = nullptr;

    for (uint64_t i = 0; i < N_OBJECTS; i++) {
        big_node_t *n = n00b_alloc_with_opts(big_node_t, &(n00b_alloc_opts_t){});
        n->seq        = i;
        n->next       = head;
        memset(n->data, (int)('a' + (i & 15)), sizeof(n->data));
        head = n;
    }

    return head;
}

int
main(int argc, char *argv[])
{
    n00b_init_simple(argc, argv);

    big_node_t *head = build_chain();

    n00b_marshal_ctx_t *ctx   = n00b_marshal_ctx_new();
    n00b_buffer_t      *image = n00b_marshal_incremental(ctx, head);
    CHECK(image != nullptr);

    uint64_t image_len = (uint64_t)n00b_buffer_len(image);
    uint64_t peak      = n00b_marshal_ctx_scratch_peak(ctx);
    uint64_t budget    = image_len * SCRATCH_BUDGET_NUMERATOR
                    / SCRATCH_BUDGET_DENOMINATOR;

    n00b_eprintf("marshal scratch bound: image=[|#|] scratch_peak=[|#|] "
                 "budget=[|#|] pct_of_image=[|#|]\n",
                 image_len,
                 peak,
                 budget,
                 (int64_t)(image_len ? (peak * 100) / image_len : 0));

    CHECK(image_len >= (uint64_t)N_OBJECTS * OBJECT_SIZE);
    CHECK(peak != 0);
    CHECK(peak <= budget);

    n00b_marshal_ctx_destroy(ctx);

    // Freeing the per-node scratch early is only safe if nothing downstream
    // reads it, so prove the image is still correct byte for byte.
    n00b_unmarshal_ctx_t *uctx  = n00b_unmarshal_ctx_new();
    auto                  roots = n00b_unmarshal_incremental(uctx, image);
    CHECK(n00b_unmarshal_ctx_status(uctx) == N00B_MARSHAL_OK);
    CHECK(n00b_list_len(roots) == 1);

    big_node_t *back  = n00b_list_get(roots, 0);
    uint64_t    count = 0;

    while (back != nullptr) {
        uint64_t i = back->seq;
        CHECK(i < N_OBJECTS);
        CHECK(back->data[0] == (char)('a' + (i & 15)));
        CHECK(back->data[OBJECT_SIZE - 1] == (char)('a' + (i & 15)));
        back = back->next;
        count++;
    }
    CHECK(count == N_OBJECTS);

    n00b_unmarshal_ctx_destroy(uctx);

    n00b_eprintf("test_marshal_scratch_bound OK\n");
    return 0;
}
