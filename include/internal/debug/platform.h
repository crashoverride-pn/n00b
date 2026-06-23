#pragma once

/**
 * @file platform.h
 * @brief Platform/arch abstraction for the debug substrate (internal).
 *
 * The platform layer owns the OS exception backend and the hardware debug
 * registers. It calls back into the registry via n00b_debug_on_hit() when a
 * slot fires. Everything here is the ABI boundary: raw OS calls live below it.
 */

#include "debug/debug.h"
#include "internal/debug/debug_internal.h"

// Bring up the OS exception backend (idempotent, thread-safe). On macOS this
// starts the Mach exception-server thread and registers EXC_BREAKPOINT.
extern n00b_debug_err_t n00b_debug_plat_init(void);

// Program a hardware watchpoint into @slot (WVR/WCR bank) on the *calling*
// thread. size is 1/2/4/8; addr need not be aligned (byte-select handles it).
extern n00b_debug_err_t n00b_debug_plat_watch_set(int32_t                 slot,
                                                  void                   *addr,
                                                  int32_t                 size,
                                                  n00b_debug_watch_kind_t kind);
extern n00b_debug_err_t n00b_debug_plat_watch_clear(int32_t slot);

// Program a hardware execute breakpoint into @slot (BVR/BCR bank). addr is an
// instruction address (4-byte aligned).
extern n00b_debug_err_t n00b_debug_plat_break_set(int32_t slot, void *addr);
extern n00b_debug_err_t n00b_debug_plat_break_clear(int32_t slot);

// Apply the full active slot-set to the *calling* thread. Called from the n00b
// thread launcher so a newly-started worker enrolls any active all-thread
// watch/breakpoints. Cheap no-op when the backend isn't initialized.
extern void n00b_debug_plat_enroll_self(void);

// Report whether a debugger/tracer is attached to this process (OS-specific).
extern bool n00b_debug_plat_is_attached(void);
