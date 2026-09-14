/*
 * The collector must not rewrite a dict bucket's non-pointer words.
 *
 * n00b-lang/n00b#365: the conduit fd registry (an untyped dict on
 * conduit_pool, a GC-visible non-moving pool) wedged sixteen threads for hours
 * with MOVING set on a live bucket, _migration_state clear and no migrator in
 * the process. The store was scanned with the conservative every-word policy,
 * and a bucket's `insert_order | flags << 32` word had aliased a from-space
 * object: the collector forwarded the object and rewrote the word, leaving the
 * upper 32 bits of the new address in `flags`.
 *
 * Case 1 reproduces that state by construction and asserts the word survives
 * a collection untouched. Case 2 asserts the store's real pointers (values)
 * are still found and forwarded. Both run against a pool-resident dict (the
 * field shape, where the store stays put) and an arena-resident dict (where
 * the store itself is copied).
 */
#include <stdio.h>
#include <assert.h>
#include <string.h>

#define N00B_USE_INTERNAL_API
#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/arena.h"
#include "core/gc.h"
#include "core/stw.h"
#include "core/atomic.h"
#include "adt/dict_untyped.h"

#define MAGIC 0xC0FFEE0000000042ULL

// Progress markers on unbuffered stderr: a crash under the collector loses
// buffered stdout, and CI has no core dumps, so this is how a red run says
// where it died.
static void
stage(const char *what)
{
    fprintf(stderr, "  .. %s\n", what);
}

// A word parked in NONE-scanned arena memory: neither a root nor rewritten,
// so it can hold a snapshot of a pointer-shaped value across a collection.
// (A stack copy cannot: the stack is scanned conservatively and rewritten.)
static __attribute__((noinline)) uint64_t *
park(n00b_arena_t *arena, uint64_t v)
{
    uint64_t *buf = n00b_alloc_array_with_opts(uint64_t,
                                               1,
                                               &(n00b_alloc_opts_t){
                                                   .allocator = (n00b_allocator_t *)arena,
                                                   .scan_kind = N00B_GC_SCAN_KIND_NONE,
                                               });
    buf[0]        = v;
    return buf;
}

static n00b_dict_untyped_t *
new_dict_on(n00b_allocator_t *al)
{
    n00b_dict_untyped_t *d
        = n00b_alloc_with_opts(n00b_dict_untyped_t, &(n00b_alloc_opts_t){.allocator = al});
    n00b_dict_untyped_init(d, .hash = n00b_hash_word, .skip_obj_hash = true, .allocator = al);
    return d;
}

static n00b_dict_untyped_bucket_t *
bucket_for(n00b_dict_untyped_t *d, uint64_t key)
{
    n00b_dict_untyped_store_t *s = n00b_atomic_load(&d->store);
    for (uint32_t i = 0; i <= s->last_slot; i++) {
        if (s->buckets[i].hv != 0 && (uint64_t)(uintptr_t)s->buckets[i].key == key) {
            return &s->buckets[i];
        }
    }
    return nullptr;
}

static void
collect(n00b_arena_t *arena)
{
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();
}

// ---------------------------------------------------------------------------
// Case 1: a bucket word that aliases a from-space object is left alone.
// ---------------------------------------------------------------------------
static __attribute__((noinline)) void
test_alias_word_not_forwarded(n00b_allocator_t *dict_al, n00b_arena_t *arena, const char *label)
{
    stage(label);
    n00b_dict_untyped_t *d = new_dict_on(dict_al);
    n00b_dict_untyped_put(d, 7, 700);
    stage("alias: dict ready");

    // The from-space object we alias. Its ONLY reference is the crafted bucket
    // word, so if the collector treats that word as a pointer it forwards the
    // object and rewrites the word.
    uint64_t *target = n00b_alloc_array_with_opts(
        uint64_t,
        4,
        &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)arena});
    target[0]      = MAGIC;
    uint64_t taddr = (uint64_t)(uintptr_t)target;
    target         = nullptr;

    n00b_dict_untyped_bucket_t *b = bucket_for(d, 7);
    assert(b != nullptr);
    uint32_t flags_before = (uint32_t)(taddr >> 32);
    b->insert_order       = (uint32_t)taddr;
    atomic_store(&b->flags, flags_before);
    uint64_t *before = park(arena, ((uint64_t)flags_before << 32) | b->insert_order);
    stage("alias: crafted, collecting");

    collect(arena);
    stage("alias: collected");

    // Re-find the bucket: an arena-resident store has moved.
    b = bucket_for(d, 7);
    assert(b != nullptr);
    uint64_t after = ((uint64_t)atomic_load(&b->flags) << 32) | b->insert_order;

    if (after != *before) {
        printf(
            "  [FAIL] %s: bucket word rewritten 0x%016llx -> 0x%016llx "
            "(flags 0x%x -> 0x%x)\n",
            label,
            (unsigned long long)*before,
            (unsigned long long)after,
            flags_before,
            atomic_load(&b->flags));
        assert(after == *before);
    }

    // Undo the crafted flags before the dict is touched again: whatever the
    // address's upper bits were, they are not a legitimate flag state.
    atomic_store(&b->flags, 0);
    stage("alias: word intact, probing key");
    bool  found = false;
    void *v     = n00b_dict_untyped_get(d, 7, &found);
    assert(found && (uint64_t)(uintptr_t)v == 700);

    printf("  [PASS] alias_word_not_forwarded (%s)\n", label);
}

// ---------------------------------------------------------------------------
// Case 2: a bucket's value pointer is still found and forwarded.
// ---------------------------------------------------------------------------
static __attribute__((noinline)) void
test_value_pointer_forwarded(n00b_allocator_t *dict_al, n00b_arena_t *arena, const char *label)
{
    n00b_dict_untyped_t *d = new_dict_on(dict_al);

    uint64_t *obj = n00b_alloc_array_with_opts(
        uint64_t,
        4,
        &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)arena});
    obj[0] = MAGIC;
    n00b_dict_untyped_put(d, 9, obj);
    uint64_t *old_addr = park(arena, (uint64_t)(uintptr_t)obj);
    obj                = nullptr; // the dict is now the only reference
    stage("forward: collecting");

    collect(arena);
    stage("forward: collected, probing key");

    bool      found = false;
    uint64_t *got   = n00b_dict_untyped_get(d, 9, &found);
    assert(found);
    assert(got != nullptr);
    // Kept alive through the bucket, moved, and the bucket rewritten to follow.
    // (Under the pin-all policy it is kept alive in place instead: same
    // address, same contents.)
    if (!n00b_gc_pin_all_policy()) {
        assert((uint64_t)(uintptr_t)got != *old_addr);
    }
    assert(got[0] == MAGIC);

    printf("  [PASS] value_pointer_forwarded (%s)\n", label);
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("test_dict_gc_scan:\n");

    // Through the runtime accessor, never the `rt` local: n00b_init may keep
    // the live runtime elsewhere, leaving the local only partly populated
    // (it did on Linux, where &rt.conduit_pool was an uninitialised pool).
    n00b_allocator_t *cpool = (n00b_allocator_t *)&n00b_get_runtime()->conduit_pool;

    // Pool-resident dict (the fd registry's shape): the store stays put and is
    // reached from the stack through the dict struct.
    {
        n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
        test_alias_word_not_forwarded(cpool, arena, "conduit_pool");
    }
    {
        n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
        test_value_pointer_forwarded(cpool, arena, "conduit_pool");
    }
    // Arena-resident dict: dict struct and store live in the collected arena,
    // so the store itself is copied and then scanned.
    {
        n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
        test_alias_word_not_forwarded((n00b_allocator_t *)arena, arena, "arena");
    }
    {
        n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);
        test_value_pointer_forwarded((n00b_allocator_t *)arena, arena, "arena");
    }

    printf("test_dict_gc_scan: OK\n");
    stage("shutting down");
    n00b_shutdown();
    return 0;
}
