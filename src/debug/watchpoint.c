#include "internal/debug/debug_internal.h"
#include "internal/debug/platform.h"

#include "core/runtime.h" // n00b_system_allocator

// Hardware watchpoints. Handles live in the system pool (non-GC, signal/
// exception-reachable). Slot bookkeeping + hit dispatch live in registry.c;
// the actual debug-register programming lives in platform/<os>.c.

n00b_result_t(n00b_debug_watchpoint_t *)
n00b_debug_watch(void *addr) _kargs
{
    n00b_debug_watch_size_t size      = N00B_DEBUG_WATCH_SIZE_8;
    n00b_debug_watch_kind_t kind      = N00B_DEBUG_WATCH_WRITE;
    n00b_debug_hit_fn       on_hit    = nullptr;
    void                   *user_data = nullptr;
    n00b_allocator_t       *allocator = nullptr;
}
{
    if (addr == nullptr) {
        return n00b_result_err(n00b_debug_watchpoint_t *,
                               N00B_DEBUG_ERR_INVALID_ARGUMENT);
    }

    n00b_debug_err_t err = n00b_debug_plat_init();
    if (err != N00B_DEBUG_OK) {
        return n00b_result_err(n00b_debug_watchpoint_t *, err);
    }

    // Default to the signal-safe system pool; honor a caller-supplied one.
    if (allocator == nullptr) {
        allocator = n00b_system_allocator();
    }
    n00b_debug_watchpoint_t *wp = n00b_alloc(n00b_debug_watchpoint_t,
                                             .allocator = allocator);
    wp->addr      = addr;
    wp->size      = size;
    wp->kind      = kind;
    wp->on_hit    = on_hit;
    wp->user_data = user_data;
    wp->slot      = -1;
    wp->enabled   = false;

    int32_t slot = n00b_debug_slot_claim_watch(wp);
    if (slot < 0) {
        return n00b_result_err(n00b_debug_watchpoint_t *, N00B_DEBUG_ERR_NO_SLOT);
    }

    err = n00b_debug_plat_watch_set(slot, addr, (int32_t)size, kind);
    if (err != N00B_DEBUG_OK) {
        n00b_debug_slot_release_watch(slot);
        return n00b_result_err(n00b_debug_watchpoint_t *, err);
    }

    wp->slot    = slot;
    wp->enabled = true;
    return n00b_result_ok(n00b_debug_watchpoint_t *, wp);
}

n00b_debug_err_t
n00b_debug_watch_clear(n00b_debug_watchpoint_t *wp)
{
    if (wp == nullptr) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    if (wp->slot >= 0) {
        n00b_debug_plat_watch_clear(wp->slot);
        n00b_debug_slot_release_watch(wp->slot);
        wp->slot = -1;
    }
    wp->enabled = false;
    // Handle storage is system-pool (bulk-freed at teardown); not freed here.
    return N00B_DEBUG_OK;
}

n00b_debug_err_t
n00b_debug_watch_enable(n00b_debug_watchpoint_t *wp)
{
    if (wp == nullptr) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    if (wp->enabled) {
        return N00B_DEBUG_OK;
    }
    if (wp->slot < 0) {
        int32_t slot = n00b_debug_slot_claim_watch(wp);
        if (slot < 0) {
            return N00B_DEBUG_ERR_NO_SLOT;
        }
        wp->slot = slot;
    }
    n00b_debug_err_t err = n00b_debug_plat_watch_set(wp->slot, wp->addr,
                                                     (int32_t)wp->size, wp->kind);
    if (err != N00B_DEBUG_OK) {
        return err;
    }
    wp->enabled = true;
    return N00B_DEBUG_OK;
}

n00b_debug_err_t
n00b_debug_watch_disable(n00b_debug_watchpoint_t *wp)
{
    if (wp == nullptr) {
        return N00B_DEBUG_ERR_INVALID_ARGUMENT;
    }
    if (wp->slot >= 0) {
        n00b_debug_plat_watch_clear(wp->slot);
    }
    wp->enabled = false;
    return N00B_DEBUG_OK;
}

void *
n00b_debug_watch_addr(n00b_debug_watchpoint_t *wp)
{
    return wp->addr;
}

n00b_debug_watch_size_t
n00b_debug_watch_size(n00b_debug_watchpoint_t *wp)
{
    return wp->size;
}

n00b_debug_watch_kind_t
n00b_debug_watch_kind(n00b_debug_watchpoint_t *wp)
{
    return wp->kind;
}

bool
n00b_debug_watch_is_enabled(n00b_debug_watchpoint_t *wp)
{
    return wp->enabled;
}
