#include "internal/debug/debug_internal.h"
#include "internal/debug/platform.h"

#include <stdatomic.h>

// Slot -> handle table for the hardware debug slots. File-scope and non-GC:
// the table is read from the OS exception-handler thread, so it must not move
// or take a parking lock. A slot's entry is the installed watchpoint handle, or
// nullptr when the slot is free. Writes happen only from install/clear under
// the watchpoint module's mutex; reads (on a hit) are lock-free.
static _Atomic(n00b_debug_watchpoint_t *) g_watch_slots[N00B_DEBUG_MAX_SLOTS];
static _Atomic(n00b_debug_breakpoint_t *) g_break_slots[N00B_DEBUG_MAX_SLOTS];

// Keep the weak thread-launcher hook in this registry object: every active
// watchpoint or breakpoint already pulls this archive member into the link.
void
n00b_debug_thread_enroll(void)
{
    n00b_debug_plat_enroll_self();
}

int32_t
n00b_debug_slot_claim_watch(n00b_debug_watchpoint_t *wp)
{
    for (int32_t i = 0; i < N00B_DEBUG_MAX_SLOTS; i++) {
        n00b_debug_watchpoint_t *expected = nullptr;
        if (atomic_compare_exchange_strong(&g_watch_slots[i], &expected, wp)) {
            return i;
        }
    }
    return -1;
}

void
n00b_debug_slot_release_watch(int32_t slot)
{
    if (slot < 0 || slot >= N00B_DEBUG_MAX_SLOTS) {
        return;
    }
    atomic_store(&g_watch_slots[slot], nullptr);
}

int32_t
n00b_debug_slot_claim_break(n00b_debug_breakpoint_t *bp)
{
    for (int32_t i = 0; i < N00B_DEBUG_MAX_SLOTS; i++) {
        n00b_debug_breakpoint_t *expected = nullptr;
        if (atomic_compare_exchange_strong(&g_break_slots[i], &expected, bp)) {
            return i;
        }
    }
    return -1;
}

void
n00b_debug_slot_release_break(int32_t slot)
{
    if (slot < 0 || slot >= N00B_DEBUG_MAX_SLOTS) {
        return;
    }
    atomic_store(&g_break_slots[slot], nullptr);
}

n00b_debug_action_t
n00b_debug_on_watch_hit(int32_t slot, n00b_debug_hit_t *hit)
{
    if (slot < 0 || slot >= N00B_DEBUG_MAX_SLOTS) {
        return N00B_DEBUG_TRAP;
    }
    n00b_debug_watchpoint_t *wp = atomic_load(&g_watch_slots[slot]);
    if (wp == nullptr || wp->on_hit == nullptr) {
        return N00B_DEBUG_TRAP; // no handler -> hand to a debugger
    }
    return wp->on_hit(hit, wp->user_data);
}

n00b_debug_action_t
n00b_debug_on_break_hit(int32_t slot, n00b_debug_hit_t *hit)
{
    if (slot < 0 || slot >= N00B_DEBUG_MAX_SLOTS) {
        return N00B_DEBUG_TRAP;
    }
    n00b_debug_breakpoint_t *bp = atomic_load(&g_break_slots[slot]);
    if (bp == nullptr || bp->on_hit == nullptr) {
        return N00B_DEBUG_TRAP; // no handler -> hand to a debugger
    }
    return bp->on_hit(hit, bp->user_data);
}

// ---- enumeration -----------------------------------------------------------

void
n00b_debug_watch_foreach(n00b_debug_watch_iter_fn fn, void *user_data)
{
    if (fn == nullptr) {
        return;
    }
    for (int32_t i = 0; i < N00B_DEBUG_MAX_SLOTS; i++) {
        n00b_debug_watchpoint_t *wp = atomic_load(&g_watch_slots[i]);
        if (wp != nullptr && !fn(wp, user_data)) {
            return;
        }
    }
}

void
n00b_debug_break_foreach(n00b_debug_break_iter_fn fn, void *user_data)
{
    if (fn == nullptr) {
        return;
    }
    for (int32_t i = 0; i < N00B_DEBUG_MAX_SLOTS; i++) {
        n00b_debug_breakpoint_t *bp = atomic_load(&g_break_slots[i]);
        if (bp != nullptr && !fn(bp, user_data)) {
            return;
        }
    }
}

// ---- hit-context accessors -------------------------------------------------

void *
n00b_debug_hit_pc(n00b_debug_hit_t *hit)
{
    return hit->pc;
}

void *
n00b_debug_hit_sp(n00b_debug_hit_t *hit)
{
    return hit->sp;
}

void *
n00b_debug_hit_addr(n00b_debug_hit_t *hit)
{
    return hit->addr;
}

uint64_t
n00b_debug_hit_reg(n00b_debug_hit_t *hit, int32_t reg)
{
    if (reg < 0 || reg > 30) {
        return 0;
    }
    return hit->regs[reg];
}

void
n00b_debug_hit_set_reg(n00b_debug_hit_t *hit, int32_t reg, uint64_t val)
{
    if (reg < 0 || reg > 30) {
        return;
    }
    hit->regs[reg]  = val;
    hit->regs_dirty = true;
}

void *
n00b_debug_hit_old_value(n00b_debug_hit_t *hit)
{
    return hit->old_value;
}

void *
n00b_debug_hit_new_value(n00b_debug_hit_t *hit)
{
    return hit->new_value;
}
