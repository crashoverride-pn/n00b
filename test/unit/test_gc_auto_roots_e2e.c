// ============================================================================
// End-to-end auto-roots reachability test (WP-003 Phase 4 / D-029).
//
// Load-bearing § 6.5b regression test for the WP-003 Phase 3+4 pair.
//
// This test pins the invariant: a TU-scope `static T *managed_singleton;`
// declared in a libn00b-compiled source gets auto-registered as a GC root
// by ncc's `--ncc-auto-gc-roots` transform (default-on per D-031), routed
// through `n00b_gc_register_roots` (Phase 2 batch API, D-012), and the
// runtime sees it as a real root by the time `n00b_collect` runs (defer
// queue + post-init flush, D-036). The 8 manual `n00b_gc_register_root`
// removals in Phase 3 (D-027) all targeted file-scope `static T *name;`
// decls of this exact shape (e.g., `src/util/path.c:31-32` cached_slash /
// cached_period); covering this shape covers those sites.
//
// Test-source-only contract: this file does NOT hand-register the
// `e2e_managed_singleton` decl with `n00b_gc_register_root` or
// `n00b_gc_register_roots`. The auto-roots transform must be the sole
// thing rooting it; if the transform stops emitting (or the runtime
// registration / defer-flush chain breaks), the magic-field assertion
// fails because the object got collected and the slot's contents now
// reference unmapped from-space memory or a reused address.
//
// Per D-029: the GC-pass mechanism is the existing
// `n00b_stop_the_world(); n00b_collect(rt->default_arena);
// n00b_restart_the_world();` idiom from `test_gc.c:104-106`. No new
// public API.
//
// Per `test_gc.c:165-176`: stack references are scoped to a
// `__attribute__((noinline))` helper. The helper writes the freshly
// allocated pointer into the TU-scope slot and returns; on return its
// stack frame is dead, so the rooted slot is the only thing keeping
// the managed object alive.
//
// Verification that this test would FAIL under
// `--ncc-no-auto-gc-roots`: with the opt-out flag added to this
// target's c_args, the transform skips emitting the per-TU root table,
// so the runtime never sees `&e2e_managed_singleton` as a root. The
// allocate-waste pressure (negative control) drops `arena_used`
// substantially, and the magic-field check on the rooted singleton
// would now hit either unmapped memory (segfault) or stale garbage
// (assertion failure). This was verified during Phase 4 implementation
// by temporarily injecting `--ncc-no-auto-gc-roots` into this test's
// c_args; the FAIL configuration is NOT committed.
// ============================================================================

#include <assert.h>

#include "n00b.h"
#include "conduit/print.h"
// Uses codegen-ABI root/static-object types from core/codegen_abi_inject.h,
// which is no longer force-included (decoupled for incremental compilation).
#include "core/codegen_abi_inject.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/gc.h"
#include "core/runtime.h"
#include "core/stw.h"

// ============================================================================
// Managed object type
// ============================================================================
//
// A small heap struct with an identifying magic word, mirroring the
// shape used throughout `test_gc.c`. Allocated via the public
// `n00b_alloc_with_opts(...)` + `ARENA_OPTS(arena)` idiom so the
// allocation lives in `rt->default_arena` — the same arena
// `n00b_collect()` will run on.

typedef struct {
    uint64_t magic;
    uint64_t tag;
    void    *placeholder; // pointer-typed slot so the type is scanned.
} e2e_managed_t;

#define E2E_MAGIC_ROOTED   UINT64_C(0xDEADBEEF42AA0001)
#define E2E_MAGIC_UNROOTED UINT64_C(0xDEADBEEF42BB0002)
#define E2E_TAG_ROOTED     UINT64_C(0xCAFEF00DAA000001)
#define E2E_TAG_UNROOTED   UINT64_C(0xCAFEF00DBB000002)

#define ARENA_OPTS(a)                                                                          \
    &(n00b_alloc_opts_t)                                                                       \
    {                                                                                          \
        .allocator = (n00b_allocator_t *)(a)                                                   \
    }

// ============================================================================
// TU-scope managed pointers
// ============================================================================
//
// `e2e_managed_singleton` is the surface under test: file-scope
// `static T *name;`. ncc's auto-roots transform sees this decl, emits
// it into a per-TU `static const n00b_gc_root_t[]` table, and emits a
// `[[gnu::constructor]]` that calls `n00b_gc_register_roots()`.
// Per D-036, that constructor fires during dynamic loader init —
// before `n00b_init` — so the entry is parked in the pre-init defer
// queue; `n00b_init` flushes the queue once `runtime->gc_roots` is
// allocated. By the time `main()` runs the test body, the runtime
// already knows about this slot.
//
// `e2e_unrooted_singleton` is the negative-control sibling: same
// shape, same file, but tagged with `[[n00b::nomap]]` so the
// auto-roots transform skips it (the attribute is detected by
// `xform_gc_globals.c::attribute_is_n00b_nomap` and stripped from
// emitted C). The runtime never sees `&e2e_unrooted_singleton` as a
// root, so the object it points to is collectible.

static e2e_managed_t                *e2e_managed_singleton;
[[n00b::nomap]] static e2e_managed_t *e2e_unrooted_singleton;

// ============================================================================
// noinline allocation helpers (drop stack refs tightly)
// ============================================================================
//
// Each helper allocates one managed object, stamps its magic word and
// tag, writes the pointer into the appropriate TU-scope slot, and
// returns. On return the helper's stack frame is dead, so the only
// remaining reference is the slot itself. This is the same pattern as
// `test_gc.c::allocate_waste()` at lines 165-176: the noinline
// boundary forces all transient pointer values to live exclusively in
// the helper frame, not in main's frame.

static __attribute__((noinline)) void
populate_rooted_singleton(n00b_arena_t *arena)
{
    e2e_managed_t *obj = n00b_alloc_with_opts(e2e_managed_t, ARENA_OPTS(arena));
    obj->magic         = E2E_MAGIC_ROOTED;
    obj->tag           = E2E_TAG_ROOTED;
    obj->placeholder   = nullptr;
    e2e_managed_singleton = obj;
}

static __attribute__((noinline)) void
populate_unrooted_singleton(n00b_arena_t *arena)
{
    e2e_managed_t *obj = n00b_alloc_with_opts(e2e_managed_t, ARENA_OPTS(arena));
    obj->magic         = E2E_MAGIC_UNROOTED;
    obj->tag           = E2E_TAG_UNROOTED;
    obj->placeholder   = nullptr;
    e2e_unrooted_singleton = obj;
}

// Allocate `count` short-lived managed objects, all immediately
// orphaned. Provides bulk reclaimable pressure so the negative-control
// "did GC actually run" assertion (`arena_used` dropped) has a clear
// signal. Mirrors `test_gc.c::allocate_waste()` exactly.
static __attribute__((noinline)) void
allocate_waste(n00b_arena_t *arena, int count)
{
    for (int i = 0; i < count; i++) {
        e2e_managed_t *waste = n00b_alloc_with_opts(e2e_managed_t,
                                                    ARENA_OPTS(arena));
        waste->magic = 0;
        waste->tag   = (uint64_t)i;
        waste->placeholder = nullptr;
    }
}

// ============================================================================
// The test
// ============================================================================

static void
test_auto_roots_rooted_object_survives_forced_gc(void)
{
    n00b_runtime_t *rt    = n00b_get_runtime();
    n00b_arena_t   *arena = rt->default_arena;

    // ------------------------------------------------------------------
    // 1. Stamp the rooted and unrooted singletons via noinline helpers.
    //    Both are file-scope statics; only `e2e_managed_singleton`
    //    should be in `rt->gc_roots`.
    // ------------------------------------------------------------------
    populate_rooted_singleton(arena);
    populate_unrooted_singleton(arena);

    // Capture the pre-GC value of the unrooted singleton's slot for
    // the post-GC negative-control comparison. We XOR-mask the value
    // so conservative stack scanning does NOT see it as a live
    // pointer.
    //
    // Without this mask the conservative scanner would see the raw
    // `uintptr_t` value sitting on the stack, treat it as a pointer
    // into from-space, copy the target object to to-space, and
    // rewrite both the stack word AND any aliases — keeping the
    // supposedly-unrooted object alive through a stack back-channel
    // and defeating the negative control. The encoded form has its
    // high bits flipped via `PTR_MASK`, which guarantees it doesn't
    // look like a valid arena address.
    //
    // Same idiom as `test_gc_stack.c::PTR_SAVE_MASK` (line 21).
    static const uintptr_t PTR_MASK = (uintptr_t)0xa5a5a5a5a5a5a5a5ULL;

    uintptr_t pre_unrooted_masked = (uintptr_t)e2e_unrooted_singleton ^ PTR_MASK;
    assert((pre_unrooted_masked ^ PTR_MASK) != 0);
    // Sanity-check the rooted slot was populated too; not masked
    // because we don't compare it post-GC (the magic-word check on
    // the heap object is the primary assertion).
    assert(e2e_managed_singleton != nullptr);

    // ------------------------------------------------------------------
    // 2. Apply bulk allocation pressure under a noinline boundary so
    //    the negative control (arena_used dropping) has a strong
    //    signal. After this returns, the only live managed object
    //    reachable from the test frame is whatever survives via
    //    `e2e_managed_singleton`.
    // ------------------------------------------------------------------
    allocate_waste(arena, 400);

    uint64_t pre_used = n00b_arena_used(arena);

    // ------------------------------------------------------------------
    // 3. Force a collection — the D-029 canonical idiom.
    // ------------------------------------------------------------------
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();

    uint64_t post_used = n00b_arena_used(arena);

    uintptr_t pre_unrooted_addr = pre_unrooted_masked ^ PTR_MASK;

    // ------------------------------------------------------------------
    // 4. Negative control: the collection must actually have reclaimed
    //    memory. With 400 short-lived waste allocations dropped before
    //    the collect, arena_used after must be substantially less than
    //    before. Mirrors `test_gc.c::test_unreachable_collected`:
    //    conservative scanning may keep a handful alive, but the bulk
    //    must be reclaimed.
    // ------------------------------------------------------------------
    assert(post_used < pre_used);
    assert(post_used < pre_used / 2);

    // ------------------------------------------------------------------
    // 5. Primary assertion: the rooted singleton's pointer is non-null
    //    AND its magic word + tag survived intact. If auto-roots were
    //    not registered, the moving collector would have reclaimed the
    //    object and the slot would either still hold the (now stale)
    //    pre-GC address (whose backing segment is unmapped — segfault
    //    on read) or would hold a forwarded address pointing into
    //    unrelated to-space memory (assertion failure on the magic
    //    word).
    //
    //    The slot SHOULD have been rewritten by the collector to point
    //    at the copied object in to-space; reading through it must
    //    yield the original magic and tag.
    // ------------------------------------------------------------------
    assert(e2e_managed_singleton != nullptr);
    assert(e2e_managed_singleton->magic == E2E_MAGIC_ROOTED);
    assert(e2e_managed_singleton->tag == E2E_TAG_ROOTED);

    // ------------------------------------------------------------------
    // 6. Negative-control sharpness check on the unrooted sibling. We
    //    do NOT dereference `e2e_unrooted_singleton` after the
    //    collect: its target lived in from-space, which has been
    //    unmapped by `n00b_collect`. Reading would segfault. What we
    //    CAN assert is that the slot itself was NOT updated to a
    //    to-space copy: the auto-roots transform skipped this decl
    //    (per `[[n00b::nomap]]`), so the runtime had no entry for
    //    `&e2e_unrooted_singleton` and the collector did not visit
    //    the slot. The pointer still holds its original from-space
    //    value.
    //
    //    By contrast, the rooted slot's address may or may not have
    //    been updated (depends on whether the collector chose a new
    //    to-space location), but its contents are guaranteed intact.
    //    The combination — rooted contents intact + unrooted slot
    //    unchanged — is consistent only with auto-roots registering
    //    the rooted decl and skipping the nomap decl.
    // ------------------------------------------------------------------
    assert((uintptr_t)e2e_unrooted_singleton == pre_unrooted_addr);

    n00b_printf("  [PASS] auto_roots rooted object survives forced GC "
                "(pre_used=[|#|], post_used=[|#|])",
                (uint64_t)pre_used,
                (uint64_t)post_used);
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    n00b_printf("Running auto-roots e2e tests...");

    test_auto_roots_rooted_object_survives_forced_gc();

    n00b_printf("All auto-roots e2e tests passed.");
    n00b_shutdown();
    return 0;
}
