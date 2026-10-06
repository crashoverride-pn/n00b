// Every table keyed by a heap object's address must still find that object
// after a copying collection moves it.
//
// Each case puts one object from a collected arena into one table, collects
// the arena so the object moves, and looks the object up by its new address.
// Every case runs, and every table that misses is named before the test fails.
//
// Not reached here: the marshal memo dict, which lives for a single marshal
// that runs with the world stopped.

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/alloc_mdata.h"
#include "core/arena.h"
#include "core/gc.h"
#include "core/runtime.h"
#include "adt/dict.h"
#include "core/oob_md_dict.h"
#include "slay/cf_label.h"
#include "slay/codegen.h"
#include "slay/parse_tree.h"
#include "internal/slay/earley_internal.h"

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);       \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

#define POINTER_MASK 0xA5A5A5A5A5A5A5A5ULL
#define ARENA_OPTS(a) &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)(a)}

typedef struct {
    uint64_t magic;
    uint64_t pad[3];
} box_t;

static n00b_arena_t *arena;
static int           missed;

static n00b_arena_t *
new_collected_arena(bool external_metadata)
{
    return n00b_new_arena(.size = 1 << 16, .use_gc = true, .no_map = !external_metadata);
}

// Collects `a` and requires that it moved the object `obj` names, given its
// address before the collection as a masked, volatile snapshot (so neither the
// stack scan nor the compiler can rewrite it along with the pointer).
#define COLLECT_AND_REQUIRE_MOVED(a, obj)                                      \
    do {                                                                       \
        volatile uintptr_t before_ = (uintptr_t)(obj) ^ POINTER_MASK;          \
        n00b_collect(a);                                                       \
        REQUIRE(((uintptr_t)(obj) ^ POINTER_MASK) != before_);                 \
    } while (0)

static void
report(const char *table, bool found)
{
    if (found) {
        printf("  [PASS] %s finds a moved key\n", table);
    }
    else {
        fprintf(stderr, "  [FAIL] %s misses a moved key\n", table);
        missed++;
    }
}

static void
test_oob_metadata(void)
{
    if (arena->vtable.metadata == nullptr) {
        printf("  [SKIP] OOB metadata: this build keeps none\n");
        return;
    }
    box_t *volatile obj = n00b_alloc_with_opts(box_t, ARENA_OPTS(arena));

    COLLECT_AND_REQUIRE_MOVED(arena, obj);

    n00b_oob_hdr_t *rec = n00b_md_get(arena->vtable.metadata, (void *)obj);
    report("OOB metadata", rec != nullptr && rec->user_ptr == (void *)obj);
}

static _Atomic int index_finalizer_runs;

static void
count_finalizer_run(void *p)
{
    (void)p;
    atomic_fetch_add(&index_finalizer_runs, 1);
}

// An object with no OOB record keeps its finalizer in rt->finalizers, which
// n00b_free consults by the object's address.
static void
test_finalizer_index(void)
{
    n00b_arena_t  *bare = new_collected_arena(false);
    box_t *volatile obj = n00b_alloc_with_opts(box_t, ARENA_OPTS(bare));
    n00b_add_finalizer((void *)obj, count_finalizer_run, nullptr);

    COLLECT_AND_REQUIRE_MOVED(bare, obj);

    n00b_free((void *)obj);
    report("finalizer index", atomic_load(&index_finalizer_runs) == 1);
}

static void
test_cf_labels(void)
{
    n00b_cf_labels_t           *labels = n00b_cf_labels_new();
    n00b_cf_label_t            *label  = n00b_alloc(n00b_cf_label_t);
    n00b_parse_tree_t *volatile node   = n00b_alloc_with_opts(n00b_parse_tree_t,
                                                            ARENA_OPTS(arena));
    n00b_parse_tree_t *key = (n00b_parse_tree_t *)node;
    n00b_dict_put(labels, key, label);

    COLLECT_AND_REQUIRE_MOVED(arena, node);

    report("slay cf_labels", n00b_cf_label_lookup(labels, (n00b_parse_tree_t *)node) == label);
}

static void
test_node_types(void)
{
    n00b_node_types_t          *types = n00b_node_types_new();
    n00b_parse_tree_t *volatile node  = n00b_alloc_with_opts(n00b_parse_tree_t,
                                                           ARENA_OPTS(arena));
    n00b_parse_tree_t *key  = (n00b_parse_tree_t *)node;
    n00b_tc_type_t    *type = nullptr;
    n00b_dict_put(types, key, type);

    COLLECT_AND_REQUIRE_MOVED(arena, node);

    bool found = false;
    key        = (n00b_parse_tree_t *)node;
    (void)n00b_dict_get(types, key, &found);
    report("slay node_types", found);
}

static void
test_earley_item_set(void)
{
    n00b_item_set_t             *set  = n00b_item_set_new();
    n00b_earley_item_t *volatile item = n00b_alloc_with_opts(n00b_earley_item_t,
                                                             ARENA_OPTS(arena));
    n00b_item_set_put(set, (n00b_earley_item_t *)item);

    COLLECT_AND_REQUIRE_MOVED(arena, item);

    report("earley item set", n00b_item_set_contains(set, (n00b_earley_item_t *)item));
}

static void
test_earley_cache(void)
{
    n00b_dict_t(n00b_earley_item_t *, void *) *cache = n00b_earley_cache_new();
    box_t                       *value = n00b_alloc(box_t);
    n00b_earley_item_t *volatile item  = n00b_alloc_with_opts(n00b_earley_item_t,
                                                              ARENA_OPTS(arena));
    n00b_earley_item_t *key = (n00b_earley_item_t *)item;
    void               *val = value;
    n00b_dict_put(cache, key, val);

    COLLECT_AND_REQUIRE_MOVED(arena, item);

    bool  found = false;
    key         = (n00b_earley_item_t *)item;
    void *got   = n00b_dict_get(cache, key, &found);
    report("earley tree-build cache", found && got == value);
}

// The table compiled code consults on every field write once any field is
// locked, keyed by the object and the field's offset.
static void
test_field_locks(void)
{
    box_t *volatile obj = n00b_alloc_with_opts(box_t, ARENA_OPTS(arena));
    n00b_cg_debug_lock_field((void *)obj, offsetof(box_t, pad));

    COLLECT_AND_REQUIRE_MOVED(arena, obj);

    report("slay field locks", n00b_cg_debug_field_is_locked((void *)obj, offsetof(box_t, pad)));
}

int
main(int argc, char **argv)
{
    // Copying collection: the point is that the key's address changes.
    setenv("N00B_GC_PIN_ALL", "0", 1);

    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    arena = new_collected_arena(true);

    test_oob_metadata();
    test_finalizer_index();
    test_cf_labels();
    test_node_types();
    test_earley_item_set();
    test_earley_cache();
    test_field_locks();

    REQUIRE(missed == 0);

    n00b_shutdown();
    return 0;
}
