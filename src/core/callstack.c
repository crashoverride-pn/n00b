/*
 * callstack.c — OS-native call-stack allocation + the canonical
 * SP->ID-word helper.
 *
 * See include/core/callstack.h for the geometry contract, the ID-word
 * write protocol, and the DF #2 (offset/alignment) and DF #3
 * (guard-page size) policy decisions.
 *
 * WP-001 Phase 2 wires n00b_thread_self() / identity to
 * n00b_callstack_id_word (worker masking branch); thread creation
 * consumes n00b_callstack_alloc in Phase 3.
 */

#include "n00b.h"
#include "core/runtime.h"
#include "core/callstack.h"
#include "core/mmaps.h"
#include "core/align.h"
#include "core/atomic.h"
#include "adt/option.h"
#include "adt/result.h"
#include "util/errno_str.h"

// mmaps.h already re-exports the PROT_*/MAP_* constants (and on Windows
// the VirtualProtect surface via core/platform.h).  The only symbol this
// file needs that mmaps.h does not provide is mprotect itself, so the
// direct <sys/mman.h> include is narrowed to the non-Windows mprotect
// path only.
#ifndef _WIN32
#include <sys/mman.h> // for mprotect (no n00b wrapper exists; see below)
#endif

// ============================================================================
// Internal helpers
// ============================================================================

// Mark a sub-region of an already-mapped stack as non-accessible (the
// guard band).  n00b has no wrapper for mprotect / VirtualProtect, so
// the raw syscall is used directly, surfaced as an n00b_result_t the
// same way n00b_check_mmap wraps mmap.  Per NCC.md ("NO LIBC ALLOWED"),
// a raw OS syscall with no n00b wrapper is permitted in a .c file; the
// result is wrapped via n00b_check_posix so callers see a typed error,
// not errno.  No wrapper is added and no helper is moved in this phase.
static n00b_result_t(int)
_n00b_callstack_protect_none(void *addr, uint64_t size)
{
#ifdef _WIN32
    DWORD old;
    if (!VirtualProtect(addr, (SIZE_T)size, PAGE_NOACCESS, &old)) {
        return n00b_result_err(int, N00B_ERR_CALLSTACK_PROTECT_FAILED);
    }
    return n00b_result_ok(int, 0);
#else
    return n00b_check_posix(mprotect(addr, (size_t)size, PROT_NONE));
#endif
}

// Unmap of an unregistered sub-range (a trimmed head/tail page band of
// the over-allocation, or the carved region itself).  These pages were
// never registered in the mmap tree, so n00b_munmap can't address them;
// n00b_safe_munmap is the canonical primitive for exactly this case (it
// tries n00b_munmap, then falls back to the raw OS unmap for
// unregistered pages), so reuse it rather than re-implement the raw
// munmap/VirtualFree fallback (D-016 §12 dedup).
static void
_n00b_callstack_raw_unmap(void *addr, uint64_t size)
{
    if (!size) {
        return;
    }
    n00b_safe_munmap(addr, (size_t)size);
}

// ============================================================================
// Allocation / free
// ============================================================================

// Impose the n00b callstack geometry over an already-mapped, S-aligned,
// S-sized region: carve the low-end guard band PROT_NONE, register the
// usable sub-region as n00b_mmap_stack (and the guard band as its own
// non-accessible record), and fill in the n00b_callstack_t bookkeeping.
// Shared by n00b_callstack_alloc (over fresh n00b_mmap pages) and
// n00b_callstack_alloc_over (over caller-owned memory).  `region` MUST be
// S-aligned; `caller_owned` is recorded on the struct so n00b_callstack_free
// can skip the unmap for caller-owned regions.  On any failure the registry
// is left balanced (every successful register is rolled back); the caller of
// this helper owns reclaiming the `region` pages themselves.
static n00b_result_t(n00b_callstack_t *)
_n00b_callstack_impose_geometry(char             *region,
                                n00b_allocator_t *allocator,
                                bool              caller_owned)
{
    uint64_t S          = N00B_CALLSTACK_REGION_SIZE;
    uint64_t guard_size = N00B_CALLSTACK_GUARD_PAGES * (uint64_t)n00b_page_size;

    char *guard_start = region;
    char *stack_low   = region + guard_size;
    char *stack_high  = region + S;

    auto prot_r = _n00b_callstack_protect_none(guard_start, guard_size);
    if (n00b_result_is_err(prot_r)) {
        return n00b_result_err(n00b_callstack_t *, n00b_result_get_err(prot_r));
    }

    // Register the usable region as n00b_mmap_stack (same kind as the
    // main-thread stack registration in thread.c) so the GC stack scan
    // finds it.  Check the option before unwrapping: a failed register
    // would otherwise assert-abort in n00b_option_get (§5).
    auto stack_reg = n00b_mmap_register(stack_low,
                                        stack_high,
                                        n00b_mmap_stack,
                                        .allocator = allocator,
                                        .perms     = n00b_mmap_perms_rw);
    if (!n00b_option_is_set(stack_reg)) {
        return n00b_result_err(n00b_callstack_t *,
                               N00B_ERR_CALLSTACK_REGISTER_FAILED);
    }

    // Register the guard band as its own non-accessible record so its
    // inaccessibility is observable via the perms record without faulting.
    auto guard_reg = n00b_mmap_register(guard_start,
                                        stack_low,
                                        n00b_mmap_stack,
                                        .allocator = allocator,
                                        .perms     = n00b_mmap_perms_no_access);
    if (!n00b_option_is_set(guard_reg)) {
        n00b_mmap_unregister(stack_low);
        return n00b_result_err(n00b_callstack_t *,
                               N00B_ERR_CALLSTACK_REGISTER_FAILED);
    }

    n00b_callstack_t *cs = n00b_alloc(n00b_callstack_t, .allocator = allocator);

    cs->region_start = region;
    cs->region_size  = S;
    cs->guard_start  = guard_start;
    cs->guard_size   = guard_size;
    cs->stack_low    = stack_low;
    cs->stack_high   = stack_high;
    cs->stack_map    = n00b_option_get(stack_reg);
    cs->guard_map    = n00b_option_get(guard_reg);
    cs->caller_owned = caller_owned;

    return n00b_result_ok(n00b_callstack_t *, cs);
}

// clang-format off
n00b_result_t(n00b_callstack_t *)
n00b_callstack_alloc(uint64_t requested_size) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
// clang-format on
{
    uint64_t S          = N00B_CALLSTACK_REGION_SIZE;
    uint64_t guard_size = N00B_CALLSTACK_GUARD_PAGES * (uint64_t)n00b_page_size;

    // The usable span is everything above the guard band, minus the ID
    // word at the top.  A request that won't fit can't share the fixed
    // power-of-2 region size, so reject it rather than break masking.
    uint64_t max_usable = S - guard_size - N00B_CALLSTACK_ID_WORD_SIZE;
    if (requested_size > max_usable) {
        return n00b_result_err(n00b_callstack_t *,
                               N00B_ERR_CALLSTACK_SIZE_TOO_LARGE);
    }

    // DF #2: n00b_mmap returns only a page-aligned region, with no
    // power-of-2 alignment knob.  Over-allocate 2*S so an S-aligned,
    // S-sized usable region can be carved from anywhere inside it, then
    // trim the surrounding head/tail pages back so only the S-aligned
    // region stays mapped.  This makes base = SP & ~(S-1) valid (D-014).
    uint64_t over_size = 2 * S;

    auto mmap_r = n00b_check_mmap(nullptr,
                                  (size_t)over_size,
                                  N00B_MPROT,
                                  N00B_MFLAG,
                                  -1,
                                  0);
    if (n00b_result_is_err(mmap_r)) {
        return n00b_result_err(n00b_callstack_t *, n00b_result_get_err(mmap_r));
    }

    char    *over_start = n00b_result_get(mmap_r);
    uint64_t over_addr  = (uint64_t)(uintptr_t)over_start;

    // Carve the S-aligned, S-sized usable region out of the 2*S mapping.
    uint64_t base       = n00b_align_ceil(over_addr, S);
    char    *region     = (char *)(uintptr_t)base;
    uint64_t head_bytes = base - over_addr;            // pages below the region.
    uint64_t tail_bytes = over_size - head_bytes - S;  // pages above the region.

    // Trim the surrounding pages (return the address space rather than
    // leave it as additional guard).  These bands were never registered.
    _n00b_callstack_raw_unmap(over_start, head_bytes);
    _n00b_callstack_raw_unmap(region + S, tail_bytes);

    // Impose the guard band + ID-word geometry and register the region.
    // On failure roll back the carved S-region we own (the helper has
    // already balanced the mmap registry).
    auto cs_r = _n00b_callstack_impose_geometry(region, allocator, false);
    if (n00b_result_is_err(cs_r)) {
        _n00b_callstack_raw_unmap(region, S);
        return cs_r;
    }

    return cs_r;
}

// clang-format off
n00b_result_t(n00b_callstack_t *)
n00b_callstack_alloc_over(n00b_callstack_region_t region) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
// clang-format on
{
    uint64_t S        = N00B_CALLSTACK_REGION_SIZE;
    uint64_t over_addr = (uint64_t)(uintptr_t)region.base;

    // DF #2: the mask base = SP & ~(S-1) must recover the region base, so
    // the usable region must be S-aligned and S-sized.  The caller's base
    // need not be S-aligned, so the region must be large enough to carve an
    // S-aligned, S-sized sub-region from anywhere inside it — i.e. at least
    // 2*S, the same over-allocate factor n00b_callstack_alloc uses.  Compute
    // the S-aligned ceiling and confirm a full S window fits before the end;
    // reject otherwise.  Reject a null base too.
    if (region.base == nullptr) {
        return n00b_result_err(n00b_callstack_t *,
                               N00B_ERR_CALLSTACK_REGION_UNUSABLE);
    }

    // Contract (DF-2): the region must be at least 2*S so an S-aligned,
    // S-sized sub-region can always be carved regardless of where the
    // caller's base falls (it need not be S-aligned).  Enforce the 2*S floor
    // unconditionally — the head_bytes + S check below is alignment-dependent
    // and would otherwise accept an exactly-S region whenever the base
    // happened to land S-aligned (mmap placement is nondeterministic), letting
    // an undersized region through on some runs but not others.
    if (region.size < 2 * S) {
        return n00b_result_err(n00b_callstack_t *,
                               N00B_ERR_CALLSTACK_REGION_UNUSABLE);
    }

    uint64_t base       = n00b_align_ceil(over_addr, S);
    uint64_t head_bytes = base - over_addr;
    // head_bytes + S must fit within the caller's region; equivalently the
    // region must be >= head_bytes + S.  This also rejects sizes < 2*S that
    // happen to have a large head offset.
    if (region.size < head_bytes + S) {
        return n00b_result_err(n00b_callstack_t *,
                               N00B_ERR_CALLSTACK_REGION_UNUSABLE);
    }

    char *carved = (char *)(uintptr_t)base;

    // Impose the same geometry as n00b_callstack_alloc, but over the
    // caller's pages: no n00b_mmap, no head/tail trim (the caller owns the
    // bytes outside the carved S window), and caller_owned = true so
    // n00b_callstack_free drops the registrations WITHOUT unmapping.  On
    // failure the helper has already balanced the mmap registry; we must
    // NOT unmap the caller's pages.
    return _n00b_callstack_impose_geometry(carved, allocator, true);
}

void
n00b_callstack_free(n00b_callstack_t *stack)
{
    if (stack == nullptr) {
        return;
    }

    // Drop both registrations (the usable region and the guard band) so the
    // GC interval tree stays balanced.  For an n00b-owned region, also unmap
    // the whole carved region in one shot (both records are sub-ranges of
    // one raw, unregistered-by-n00b_mmap mapping).  For a CALLER-OWNED region
    // (custom_stack, D-025), the backing pages belong to the caller: drop the
    // registrations only and leave the pages mapped — unmapping them here
    // would be a use-after-free / double-free of live caller memory.
    n00b_mmap_unregister(stack->stack_low);
    n00b_mmap_unregister(stack->guard_start);
    if (!stack->caller_owned) {
        _n00b_callstack_raw_unmap(stack->region_start, stack->region_size);
    }
}

// ============================================================================
// Callstack pool / free-list (WP-3a Phase 2, D-034)
//
// A simple keep-N free-list of whole 8 MiB callstack regions, held on the
// runtime so spawn can recycle a dead worker's region instead of unmapping +
// re-mmapping (glibc stack-cache / Go stack-pool precedent).  A pooled region
// keeps its mmap-tree registrations and guard band LIVE — the geometry
// contract has each new worker rewrite the ID word at entry, so a reused region
// needs no re-registration.  Guarded by a tiny test-and-set spinlock on the
// runtime (rt->callstack_pool_lock): the critical sections are O(1) pointer
// splices, never blocking.
//
// Reclamation onto this list happens ONLY at OS-confirmed worker death (the
// reaper calls n00b_callstack_pool_return); n00b_thread_spawn draws from it via
// n00b_callstack_pool_get.  Returning a stack to the pool while a worker is
// still on it would be catastrophic reuse-while-live — the OS-death gate in the
// reaper (thread.c) is what makes pooling sound.
// ============================================================================

static inline void
_n00b_callstack_pool_lock(n00b_runtime_t *rt)
{
    uint32_t expected;
    do {
        expected = 0;
    } while (!n00b_cas(&rt->callstack_pool_lock, &expected, 1));
}

static inline void
_n00b_callstack_pool_unlock(n00b_runtime_t *rt)
{
    n00b_atomic_store(&rt->callstack_pool_lock, 0);
}

// clang-format off
n00b_result_t(n00b_callstack_t *)
n00b_callstack_pool_get() _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
// clang-format on
{
    n00b_runtime_t *rt = n00b_get_runtime();

    if (rt != nullptr) {
        _n00b_callstack_pool_lock(rt);
        n00b_callstack_t *cs = rt->callstack_pool;
        if (cs != nullptr) {
            rt->callstack_pool = cs->pool_next;
            rt->callstack_pool_count--;
            _n00b_callstack_pool_unlock(rt);
            cs->pool_next = nullptr;
            return n00b_result_ok(n00b_callstack_t *, cs);
        }
        _n00b_callstack_pool_unlock(rt);
    }

    // Pool miss (or no runtime): allocate a fresh region.  Thread the
    // caller's bookkeeping allocator through to the fallback.
    return n00b_callstack_alloc(0, .allocator = allocator);
}

void
n00b_callstack_pool_return(n00b_callstack_t *stack)
{
    if (stack == nullptr) {
        return;
    }

    // Caller-owned (custom_stack) regions are never pooled — the backing
    // pages belong to the caller.  n00b_callstack_free drops the mmap-tree
    // registrations WITHOUT unmapping the caller's memory.
    if (stack->caller_owned) {
        n00b_callstack_free(stack);
        return;
    }

    n00b_runtime_t *rt = n00b_get_runtime();
    if (rt == nullptr) {
        // No runtime to pool onto: just reclaim the region.
        n00b_callstack_free(stack);
        return;
    }

    _n00b_callstack_pool_lock(rt);
    if (rt->callstack_pool_count >= N00B_CALLSTACK_POOL_MAX) {
        // Keep-N cap reached (DF-4): unmap rather than retain.  Release the
        // lock first so n00b_callstack_free's mmap-tree work is not under the
        // pool spinlock.
        _n00b_callstack_pool_unlock(rt);
        n00b_callstack_free(stack);
        return;
    }
    stack->pool_next   = rt->callstack_pool;
    rt->callstack_pool = stack;
    rt->callstack_pool_count++;
    _n00b_callstack_pool_unlock(rt);
}

// ============================================================================
// Canonical O(1), lock-free SP -> region-base -> ID-word recovery
// ============================================================================

uint64_t *
n00b_callstack_id_word(void *sp, void **region_base_out)
{
    // O(1), lock-free (D-004, D-014): worker callstacks are S-aligned and
    // S-sized, so the region base is just the SP masked to the S boundary.
    // No mmap interval-tree lookup, no lock.  The ID word sits at the top
    // of the region (base of the downward-growing stack), at the fixed
    // offset S - 8 from the base.
    uint64_t base    = (uint64_t)(uintptr_t)sp & N00B_CALLSTACK_REGION_MASK;
    uint64_t id_addr = base + N00B_CALLSTACK_REGION_SIZE
                     - N00B_CALLSTACK_ID_WORD_SIZE;

    if (region_base_out != nullptr) {
        *region_base_out = (void *)(uintptr_t)base;
    }

    return (uint64_t *)(uintptr_t)id_addr;
}

// ============================================================================
// Error-code accessor (§5.5)
// ============================================================================

n00b_string_t *
n00b_callstack_err_str(n00b_err_t err)
{
    switch (err) {
    case N00B_ERR_CALLSTACK_SIZE_TOO_LARGE:
        return r"callstack: requested size exceeds the fixed region's usable span";
    case N00B_ERR_CALLSTACK_REGISTER_FAILED:
        return r"callstack: mmap-interval-tree registration failed";
    case N00B_ERR_CALLSTACK_PROTECT_FAILED:
        return r"callstack: failed to mark the guard band non-accessible";
    case N00B_ERR_CALLSTACK_REGION_UNUSABLE:
        return r"callstack: custom_stack region too small or un-alignable "
               "(need >= 2 * region size)";
    default:
        // Not a library-domain code -- it is a real POSIX errno surfaced
        // verbatim from the underlying mmap / mprotect primitives.
        return n00b_errno_str(err);
    }
}
