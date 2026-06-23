#include "internal/debug/debug_internal.h"
#include "internal/debug/platform.h"

#include "core/string.h"
#include "core/platform.h" // base_nanosleep_ns

// Called by the n00b thread launcher (weak hook) on every newly-started worker
// so it enrolls any active all-thread watch/breakpoints. Cheap no-op when the
// debug backend has never been initialized.
void
n00b_debug_thread_enroll(void)
{
    n00b_debug_plat_enroll_self();
}

// Process-wide helpers and the error-string table. Watchpoint and breakpoint
// installation live in watchpoint.c and breakpoint.c respectively.

n00b_string_t *
n00b_debug_err_str(n00b_debug_err_t e)
{
    switch (e) {
    case N00B_DEBUG_OK:
        return r"ok";
    case N00B_DEBUG_ERR_NO_SLOT:
        return r"no hardware debug slots available";
    case N00B_DEBUG_ERR_INVALID_ARGUMENT:
        return r"invalid argument";
    case N00B_DEBUG_ERR_SIGNAL_HANDLER:
        return r"failed to install exception/signal backend";
    case N00B_DEBUG_ERR_MEMORY_PROTECTION:
        return r"target code is not writable";
    case N00B_DEBUG_ERR_UNSUPPORTED:
        return r"unsupported on this architecture/platform";
    case N00B_DEBUG_ERR_INTERNAL:
        return r"internal debug-library error";
    case N00B_DEBUG_ERR_TIMEOUT:
        return r"timed out waiting for a debugger";
    default:
        return r"unknown debug error";
    }
}

void
n00b_debug_trap(void)
{
#if defined(__aarch64__)
    __asm__ volatile("brk #0");
#elif defined(__x86_64__)
    __asm__ volatile("int3");
#endif
}

bool
n00b_debug_is_attached(void)
{
    return n00b_debug_plat_is_attached();
}

n00b_debug_err_t
n00b_debug_wait_for_debugger() _kargs
{
    int32_t timeout_ms = -1;
}
{
    int32_t waited = 0;
    while (!n00b_debug_is_attached()) {
        if (timeout_ms >= 0 && waited >= timeout_ms) {
            return N00B_DEBUG_ERR_TIMEOUT;
        }
        base_nanosleep_ns(10ull * 1000 * 1000); // 10ms
        waited += 10;
    }
    return N00B_DEBUG_OK;
}
