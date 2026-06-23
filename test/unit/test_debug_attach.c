#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "core/runtime.h"
#include "debug/debug.h"

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running debug attach tests...\n");

    bool attached = n00b_debug_is_attached();
    printf("  is_attached = %d\n", (int)attached);

    if (!attached) {
        // No debugger in the harness: a zero timeout must report not-attached.
        n00b_debug_err_t e = n00b_debug_wait_for_debugger(.timeout_ms = 0);
        assert(e != N00B_DEBUG_OK);
    }
    else {
        // Already attached: returns OK immediately.
        assert(n00b_debug_wait_for_debugger(.timeout_ms = 0) == N00B_DEBUG_OK);
    }

    printf("  [PASS] attach\n");
    printf("All debug attach tests passed.\n");
    n00b_shutdown();
    return 0;
}
