#pragma once

/**
 * @file debug_internal.h
 * @brief Internal definitions for the debug substrate (not a public surface).
 */

#include "debug/debug.h"

// Number of hardware debug slots (watchpoints + hardware breakpoints share
// this pool). ARM64 implementations vary (2..16); 4 is the safe common floor
// and matches the x86-64 DR0-DR3 count. A platform may override it before this
// header is reached.
#if !defined(N00B_DEBUG_MAX_SLOTS)
#define N00B_DEBUG_MAX_SLOTS 4
#endif

// CPU state captured at a hit. Filled by the platform layer on the
// exception-handler thread; passed to the user callback. Register edits are
// staged here and written back to the trapped thread when the callback returns
// N00B_DEBUG_CONTINUE.
struct n00b_debug_hit_t {
    void    *pc;
    void    *sp;
    void    *addr;       // watched / breakpoint address that fired
    void    *old_value;  // (watch) prior word at addr; best-effort
    void    *new_value;  // (watch) value the faulting store writes; best-effort
    uint64_t regs[31];   // GPR snapshot; valid range is platform-dependent:
                         // arm64 uses [0..30] (x0..x30), x86-64 uses [0..15]
                         // (DWARF order rax,rdx,rcx,rbx,rsi,rdi,rbp,rsp,r8..r15)
    void    *plat;       // opaque platform handle for register write-back
    bool     regs_dirty; // a set_reg/set_pc edit is pending
};

// ---- registry.c: slot <-> handle tables + hit dispatch ---------------------
//
// Watchpoints (data, WVR/WCR) and hardware breakpoints (instruction, BVR/BCR)
// are independent register banks on ARM64, so each gets its own slot pool. A
// slot's entry is the installed handle, or nullptr when free. Writes happen
// from install/clear; reads (on a hit) are lock-free on the exception thread.

// Claim/release a free watchpoint slot; returns -1 if none free.
extern int32_t n00b_debug_slot_claim_watch(n00b_debug_watchpoint_t *wp);
extern void    n00b_debug_slot_release_watch(int32_t slot);

// Claim/release a free breakpoint slot; returns -1 if none free.
extern int32_t n00b_debug_slot_claim_break(n00b_debug_breakpoint_t *bp);
extern void    n00b_debug_slot_release_break(int32_t slot);

// Called by the platform layer when a slot fires. Looks up the handle, runs its
// callback (or returns N00B_DEBUG_TRAP when none), and returns the action.
extern n00b_debug_action_t n00b_debug_on_watch_hit(int32_t slot, n00b_debug_hit_t *hit);
extern n00b_debug_action_t n00b_debug_on_break_hit(int32_t slot, n00b_debug_hit_t *hit);
