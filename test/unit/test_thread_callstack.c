#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/callstack.h"
#include "core/mmaps.h"
#include "core/align.h"

// ============================================================================
// WP-001 Phase 1 regression test: OS call-stack allocation + the single
// canonical O(1), lock-free SP -> region-base -> ID-word recovery helper
// (D-014: workers mask base = SP & ~(S-1); main-thread recovery is Phase 2).
//
// Asserts (per the Phase-1 DoD / regression-test contract):
//   - the usable region is registered as an n00b_mmap_stack record;
//   - the carved region is S-aligned and S-sized (so masking is valid);
//   - the guard band is non-accessible, verified via the perms record
//     (n00b_mmap_perms_no_access) -- NOT by faulting;
//   - the ID-word slot is readable/writable;
//   - the recovery helper maps several in-region SPs to the SAME region
//     base and the SAME ID-word address via the O(1) masking path;
//   - free deregisters both records.
// ============================================================================

// ----------------------------------------------------------------------------
// 1. Allocation registers the usable region as n00b_mmap_stack, and the
//    carved region is S-aligned + S-sized.
// ----------------------------------------------------------------------------

static void
test_callstack_region_registered(void)
{
    auto r = n00b_callstack_alloc(0); // default size
    assert(n00b_result_is_ok(r));
    n00b_callstack_t *cs = n00b_result_get(r);

    // The carved region is exactly S bytes and S-aligned, which is what
    // makes the masking-based recovery valid.
    assert(cs->region_size == N00B_CALLSTACK_REGION_SIZE);
    assert(((uint64_t)(uintptr_t)cs->region_start
            & (N00B_CALLSTACK_REGION_SIZE - 1))
           == 0);
    assert((char *)cs->stack_high
           == (char *)cs->region_start + N00B_CALLSTACK_REGION_SIZE);

    // Look the usable region up by an address inside it.
    void *mid     = (char *)cs->stack_low + (cs->region_size / 2);
    auto  map_opt = n00b_mmap_by_address(mid);
    assert(n00b_option_is_set(map_opt));

    n00b_mmap_info_t *map = n00b_option_get(map_opt);
    assert(n00b_mmap_get_kind(map) == n00b_mmap_stack);
    assert(map->start == (uint64_t)(uintptr_t)cs->stack_low);
    assert(map->end == (uint64_t)(uintptr_t)cs->stack_high);

    n00b_callstack_free(cs);
    printf("  [PASS] callstack_region_registered\n");
}

// ----------------------------------------------------------------------------
// 2. The guard band is non-accessible (checked via the perms record).
// ----------------------------------------------------------------------------

static void
test_callstack_guard_no_access(void)
{
    auto r = n00b_callstack_alloc(0);
    assert(n00b_result_is_ok(r));
    n00b_callstack_t *cs = n00b_result_get(r);

    // The guard band lives at the low end of the region.
    void *guard_mid = (char *)cs->guard_start + (cs->guard_size / 2);
    auto  gmap_opt  = n00b_mmap_by_address(guard_mid);
    assert(n00b_option_is_set(gmap_opt));

    n00b_mmap_info_t *gmap = n00b_option_get(gmap_opt);
    assert(gmap->perms == n00b_mmap_perms_no_access);
    // Non-overlapping: the guard record is distinct from the usable one.
    assert(gmap->start == (uint64_t)(uintptr_t)cs->guard_start);
    assert(gmap->end == (uint64_t)(uintptr_t)cs->stack_low);

    n00b_callstack_free(cs);
    printf("  [PASS] callstack_guard_no_access\n");
}

// ----------------------------------------------------------------------------
// 3. The ID-word slot is readable/writable.
// ----------------------------------------------------------------------------

static void
test_callstack_id_word_rw(void)
{
    auto r = n00b_callstack_alloc(0);
    assert(n00b_result_is_ok(r));
    n00b_callstack_t *cs = n00b_result_get(r);

    void     *anchor  = (char *)cs->stack_high - 64; // an SP inside the region
    uint64_t *id_word = n00b_callstack_id_word(anchor, nullptr);

    // The ID word must lie within the usable region, at the fixed offset
    // S - 8 from the region base.
    assert((char *)id_word >= (char *)cs->stack_low);
    assert((char *)id_word < (char *)cs->stack_high);
    assert((char *)id_word
           == (char *)cs->region_start + N00B_CALLSTACK_REGION_SIZE
                  - N00B_CALLSTACK_ID_WORD_SIZE);

    *id_word = 0xdeadbeefcafef00dULL;
    assert(*id_word == 0xdeadbeefcafef00dULL);

    n00b_callstack_free(cs);
    printf("  [PASS] callstack_id_word_rw\n");
}

// ----------------------------------------------------------------------------
// 4. Recovery maps several in-region SPs to the same base + ID-word via
//    the O(1) masking path (D-014).  The main thread's kernel stack is
//    NOT exercised here -- its recovery is the Phase-2 range check.
// ----------------------------------------------------------------------------

static void
test_callstack_recovery_stable(void)
{
    auto r = n00b_callstack_alloc(0);
    assert(n00b_result_is_ok(r));
    n00b_callstack_t *cs = n00b_result_get(r);

    void *sps[4] = {
        (char *)cs->stack_low,
        (char *)cs->stack_low + n00b_page_size,
        (char *)cs->stack_low + (cs->region_size / 2),
        (char *)cs->stack_high - 8,
    };

    void     *base0    = nullptr;
    uint64_t *id_word0 = nullptr;

    for (int i = 0; i < 4; i++) {
        void     *base    = nullptr;
        uint64_t *id_word = n00b_callstack_id_word(sps[i], &base);

        // Masking recovers the carved region base (== region_start).
        assert(base == cs->region_start);

        if (i == 0) {
            base0    = base;
            id_word0 = id_word;
        }
        else {
            assert(base == base0);
            assert(id_word == id_word0);
        }
    }

    n00b_callstack_free(cs);
    printf("  [PASS] callstack_recovery_stable\n");
}

// ----------------------------------------------------------------------------
// 5. Free deregisters both records.
// ----------------------------------------------------------------------------

static void
test_callstack_free_deregisters(void)
{
    auto r = n00b_callstack_alloc(0);
    assert(n00b_result_is_ok(r));
    n00b_callstack_t *cs = n00b_result_get(r);

    void *body_mid  = (char *)cs->stack_low + (cs->region_size / 2);
    void *guard_mid = (char *)cs->guard_start + (cs->guard_size / 2);

    // Snapshot the addresses before freeing (cs is freed memory after).
    void *body_probe  = body_mid;
    void *guard_probe = guard_mid;

    n00b_callstack_free(cs);

    auto body_opt  = n00b_mmap_by_address(body_probe);
    auto guard_opt = n00b_mmap_by_address(guard_probe);

    assert(!n00b_option_is_set(body_opt));
    assert(!n00b_option_is_set(guard_opt));

    printf("  [PASS] callstack_free_deregisters\n");
}

// ----------------------------------------------------------------------------
// 6. Library-domain error codes are negative (so they cannot collide with a
//    positive errno) and the err_str accessor stringifies them (§5.1/§5.5).
// ----------------------------------------------------------------------------

static void
test_callstack_err_codes(void)
{
    // All three domain codes must be negative -- a positive errno can never
    // alias one.
    assert(N00B_ERR_CALLSTACK_SIZE_TOO_LARGE < 0);
    assert(N00B_ERR_CALLSTACK_REGISTER_FAILED < 0);
    assert(N00B_ERR_CALLSTACK_PROTECT_FAILED < 0);

    // The accessor returns a non-null description for each domain code and
    // for a real errno (folded through n00b_errno_str at the default case).
    assert(n00b_callstack_err_str(N00B_ERR_CALLSTACK_SIZE_TOO_LARGE)
           != nullptr);
    assert(n00b_callstack_err_str(N00B_ERR_CALLSTACK_REGISTER_FAILED)
           != nullptr);
    assert(n00b_callstack_err_str(N00B_ERR_CALLSTACK_PROTECT_FAILED)
           != nullptr);
    assert(n00b_callstack_err_str(EINVAL) != nullptr);

    // An over-large request must produce the SIZE_TOO_LARGE domain code,
    // not a positive errno.
    auto r = n00b_callstack_alloc(N00B_CALLSTACK_REGION_SIZE * 2);
    assert(n00b_result_is_err(r));
    assert(n00b_result_get_err(r) == N00B_ERR_CALLSTACK_SIZE_TOO_LARGE);

    printf("  [PASS] callstack_err_codes\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running thread_callstack tests...\n");

    test_callstack_region_registered();
    test_callstack_guard_no_access();
    test_callstack_id_word_rw();
    test_callstack_recovery_stable();
    test_callstack_free_deregisters();
    test_callstack_err_codes();

    printf("All thread_callstack tests passed.\n");
    n00b_shutdown();
    return 0;
}
