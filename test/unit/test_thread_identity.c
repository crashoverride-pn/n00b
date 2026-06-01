#include <stdio.h>
#include <assert.h>
#include <errno.h>

#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/alloc.h"
#include "core/mmaps.h"
#include "util/dynamic_lib.h"

// ============================================================================
// WP-001 Phase 2 regression test: TLS-free thread identity on the main
// (kernel) stack + struct consolidation.
//
// Exercised on the MAIN thread only (no workers spawned by the test;
// workers are Phase 3).  Asserts, per the Phase-2 DoD / regression
// contract:
//   - n00b_thread_self() returns the main thread's runtime-owned
//     n00b_thread_t *, and it equals rt->threads[id].thread;
//   - the recovered slot id is the main slot (N00B_MAIN_THREAD_SLOT) and
//     id_info.parts.id matches;
//   - the O(1) range check maps several main-stack SPs to the same
//     n00b_thread_t * (identity is stable across call depth);
//   - the de-TLS'd scoped allocator override round-trips through
//     self()->current_allocator;
//   - the de-TLS'd dynamic-lib last-error path round-trips per-thread;
//   - the de-TLS'd regex-nulls scratch slot lives in self();
//   - the main thread's stack_base / stack_top are sane after the
//     OS-native discovery rewrite (top inside [lo, hi), base == hi).
// ============================================================================

// ----------------------------------------------------------------------------
// 1. self() resolves to the runtime-owned struct with the right id.
// ----------------------------------------------------------------------------

static void
test_self_is_runtime_owned(void)
{
    n00b_runtime_t *rt   = n00b_get_runtime();
    n00b_thread_t  *self = n00b_thread_self();

    assert(self != nullptr);

    int32_t id = self->id_info.parts.id;
    assert(id == (int32_t)N00B_MAIN_THREAD_SLOT);

    // The canonical home is rt->threads[slot].thread.
    n00b_thread_t *from_slot = n00b_atomic_load(&rt->threads[id].thread);
    assert(from_slot == self);

    // The accessor inlines agree with the resolved struct.
    assert(n00b_thread_id() == id);
    assert(n00b_thread_unique_id() == self->id_info.unique_id);
    assert(n00b_thread_generation() == self->id_info.parts.generation);

    printf("  [PASS] self_is_runtime_owned\n");
}

// ----------------------------------------------------------------------------
// 2. Identity is stable across call depth (the O(1) range check resolves
//    every main-stack SP to the same struct).
// ----------------------------------------------------------------------------

[[gnu::noinline]] static n00b_thread_t *
deep_self(int depth)
{
    if (depth > 0) {
        // A fresh frame at a different SP; must still resolve identically.
        return deep_self(depth - 1);
    }
    return n00b_thread_self();
}

static void
test_identity_stable_across_depth(void)
{
    n00b_thread_t *top = n00b_thread_self();

    for (int d = 0; d < 8; d++) {
        n00b_thread_t *deep = deep_self(d);
        assert(deep == top);
    }

    printf("  [PASS] identity_stable_across_depth\n");
}

// ----------------------------------------------------------------------------
// 3. The main record's stored bounds bracket the current SP (the O(1)
//    range-check inputs are correct).
// ----------------------------------------------------------------------------

static void
test_main_record_bounds(void)
{
    n00b_thread_t        *self = n00b_thread_self();
    n00b_thread_record_t *rec  = self->record;

    void *lo = n00b_atomic_load(&rec->stack_lo);
    void *hi = n00b_atomic_load(&rec->stack_hi);
    assert(lo != nullptr);
    assert(hi != nullptr);
    assert(lo < hi);

    void *probe = (void *)&self;
    assert(probe >= lo && probe < hi);

    printf("  [PASS] main_record_bounds\n");
}

// ----------------------------------------------------------------------------
// 4. Scoped allocator override round-trips through self()->current_allocator.
// ----------------------------------------------------------------------------

static void
test_scoped_allocator(void)
{
    n00b_runtime_t   *rt   = n00b_get_runtime();
    n00b_thread_t    *self = n00b_thread_self();
    n00b_allocator_t *some = (n00b_allocator_t *)&rt->system_pool;

    // No override installed by default.
    assert(n00b_current_allocator() == self->current_allocator);

    n00b_allocator_t *prev = n00b_set_current_allocator(some);
    assert(self->current_allocator == some);
    assert(n00b_current_allocator() == some);

    n00b_restore_current_allocator(prev);
    assert(self->current_allocator == prev);

    // The push/restore alias pair exercises the same per-thread field.
    n00b_allocator_t *prev2 = n00b_push_current_allocator(some);
    assert(n00b_current_allocator() == some);
    assert(n00b_thread_self()->current_allocator == some);
    n00b_restore_current_allocator(prev2);
    assert(n00b_current_allocator() == prev);

    printf("  [PASS] scoped_allocator\n");
}

// ----------------------------------------------------------------------------
// 5. Dynamic-lib last-error is a per-thread field reached via self().
// ----------------------------------------------------------------------------

static void
test_dl_last_error_field(void)
{
    n00b_thread_t *self = n00b_thread_self();

    // Force an error so the per-thread slot is populated: opening an
    // empty path is rejected before any dlopen.
    n00b_result_t(n00b_dynamic_lib_t *) r = n00b_dynamic_lib_open(
        n00b_string_empty());
    assert(n00b_result_is_err(r));

    n00b_string_t *err = n00b_dynamic_lib_last_error();
    assert(err != nullptr);
    // The accessor returns the value held in the per-thread field.
    assert(err == self->dl_last_error);

    printf("  [PASS] dl_last_error_field\n");
}

// ----------------------------------------------------------------------------
// 6. The regex-nulls scratch slot lives in self() (NullsId-shaped uint32).
// ----------------------------------------------------------------------------

static void
test_regex_nulls_scratch_field(void)
{
    n00b_thread_t *self = n00b_thread_self();

    // The field exists and is writable as a per-thread uint32 slot; the
    // nulls cache writes it through (NullsId *)&self->regex_nulls_last.
    self->regex_nulls_last = 0xabcdu;
    assert(self->regex_nulls_last == 0xabcdu);

    printf("  [PASS] regex_nulls_scratch_field\n");
}

// ----------------------------------------------------------------------------
// 7. Main stack base/top are sane after the OS-native discovery rewrite.
// ----------------------------------------------------------------------------

static void
test_main_stack_base_top(void)
{
    n00b_thread_t        *self = n00b_thread_self();
    n00b_thread_record_t *rec  = self->record;

    void *lo = n00b_atomic_load(&rec->stack_lo);
    void *hi = n00b_atomic_load(&rec->stack_hi);

    // stack_base is the high end; stack_top is captured at init and is a
    // current-frame address that must sit inside the discovered range.
    assert(self->stack_base == hi);
    assert(self->stack_top != nullptr);
    assert(self->stack_top >= lo && self->stack_top < hi);

    // The registered mmap_stack record covers the current SP.
    assert(n00b_current_thread_stack_contains((void *)&self));

    printf("  [PASS] main_stack_base_top\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running thread_identity tests...\n");

    test_self_is_runtime_owned();
    test_identity_stable_across_depth();
    test_main_record_bounds();
    test_scoped_allocator();
    test_dl_last_error_field();
    test_regex_nulls_scratch_field();
    test_main_stack_base_top();

    printf("All thread_identity tests passed.\n");
    n00b_shutdown();
    return 0;
}
