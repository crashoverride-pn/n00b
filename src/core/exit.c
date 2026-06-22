#include <unistd.h>
#include <signal.h>

#include "n00b.h"
#include "core/exit.h"
#include "core/syscall.h" // n00b_raw_exit -- libc-free, worker-safe

static bool exiting           = false;
static int  saved_exit_code   = 0;
bool        n00b_abort_signal = false;

[[noreturn]] void
n00b_abort(void)
{
    saved_exit_code   = 139;
    exiting           = true;
    n00b_abort_signal = true;

    // NEVER call libc abort(): it calls pthread_self(), which dereferences the
    // pthread TSD that raw n00b OS-thread workers do not have, so it traps
    // (EXC_BREAKPOINT) instead of aborting -- swallowing the diagnostic.
    //
    // Raise SIGABRT via the kill() syscall (no TSD) so n00b's own crash handler
    // (installed for SIGABRT in n00b_crash_init) dumps context.  SIGABRT is
    // delivered asynchronously (not a synchronous fault that re-executes), so
    // the handler returns here; guarantee termination with the raw exit syscall.
    kill(getpid(), SIGABRT);
    n00b_raw_exit(saved_exit_code);
    __builtin_unreachable();
}

bool
n00b_current_process_is_exiting(void)
{
    return exiting;
}
