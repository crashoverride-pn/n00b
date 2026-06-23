#include "internal/debug/debug_internal.h"
#include "internal/debug/platform.h"

#include "core/runtime.h" // n00b_system_allocator

// Hardware execute breakpoints (BVR/BCR bank). Handles live in the system pool
// (non-GC, exception-reachable). Software breakpoints (INT3/BRK) land in P3.

n00b_result_t(n00b_debug_breakpoint_t *)
n00b_debug_break(void *addr) _kargs
{
    n00b_debug_break_kind_t kind      = N00B_DEBUG_BREAK_HW;
    n00b_debug_hit_fn       on_hit    = nullptr;
    void                   *user_data = nullptr;
    n00b_allocator_t       *allocator = nullptr;
}
{
    if (addr == nullptr) {
        return n00b_result_err(n00b_debug_breakpoint_t *,
                               N00B_DEBUG_ERR_INVALID_ARGUMENT);
    }
    if (kind != N00B_DEBUG_BREAK_HW) {
        // Software breakpoints arrive in P3.
        return n00b_result_err(n00b_debug_breakpoint_t *,
                               N00B_DEBUG_ERR_UNSUPPORTED);
    }

    n00b_debug_err_t err = n00b_debug_plat_init();
    if (err != N00B_DEBUG_OK) {
        return n00b_result_err(n00b_debug_breakpoint_t *, err);
    }

    // Default to the signal-safe system pool; honor a caller-supplied one.
    if (allocator == nullptr) {
        allocator = n00b_system_allocator();
    }
    n00b_debug_breakpoint_t *bp = n00b_alloc(n00b_debug_breakpoint_t,
                                             .allocator = allocator);
    bp->addr      = addr;
    bp->kind      = kind;
    bp->on_hit    = on_hit;
    bp->user_data = user_data;
    bp->slot      = -1;
    bp->enabled   = false;

    int32_t slot = n00b_debug_slot_claim_break(bp);
    if (slot < 0) {
        return n00b_result_err(n00b_debug_breakpoint_t *, N00B_DEBUG_ERR_NO_SLOT);
    }

    err = n00b_debug_plat_break_set(slot, addr);
    if (err != N00B_DEBUG_OK) {
        n00b_debug_slot_release_break(slot);
        return n00b_result_err(n00b_debug_breakpoint_t *, err);
    }

    bp->slot    = slot;
    bp->enabled = true;
    return n00b_result_ok(n00b_debug_breakpoint_t *, bp);
}

n00b_debug_err_t
n00b_debug_break_clear(n00b_debug_breakpoint_t *bp)
{
    if (bp == nullptr) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    if (bp->slot >= 0) {
        n00b_debug_plat_break_clear(bp->slot);
        n00b_debug_slot_release_break(bp->slot);
        bp->slot = -1;
    }
    bp->enabled = false;
    return N00B_DEBUG_OK;
}

n00b_debug_err_t
n00b_debug_break_enable(n00b_debug_breakpoint_t *bp)
{
    if (bp == nullptr) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    if (bp->enabled) {
        return N00B_DEBUG_OK;
    }
    if (bp->slot < 0) {
        int32_t slot = n00b_debug_slot_claim_break(bp);
        if (slot < 0) {
            return N00B_DEBUG_ERR_NO_SLOT;
        }
        bp->slot = slot;
    }
    n00b_debug_err_t err = n00b_debug_plat_break_set(bp->slot, bp->addr);
    if (err != N00B_DEBUG_OK) {
        return err;
    }
    bp->enabled = true;
    return N00B_DEBUG_OK;
}

n00b_debug_err_t
n00b_debug_break_disable(n00b_debug_breakpoint_t *bp)
{
    if (bp == nullptr) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    if (bp->slot >= 0) {
        n00b_debug_plat_break_clear(bp->slot);
    }
    bp->enabled = false;
    return N00B_DEBUG_OK;
}

void *
n00b_debug_break_addr(n00b_debug_breakpoint_t *bp)
{
    return bp->addr;
}

n00b_debug_break_kind_t
n00b_debug_break_kind(n00b_debug_breakpoint_t *bp)
{
    return bp->kind;
}

bool
n00b_debug_break_is_enabled(n00b_debug_breakpoint_t *bp)
{
    return bp->enabled;
}
