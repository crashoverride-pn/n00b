#include <stdio.h>
#include <assert.h>

#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/runtime.h"
#include "core/string.h"

// ============================================================================
// Regression: n00b_shutdown() called from inside a gc-framed function.
//
// The CLI pattern (e.g. wax/crayon) runs, per command:
//     n00b_runtime_t rt;             // stack-local
//     n00b_init(&rt, ...);
//     ... build/print ...
//     n00b_shutdown();               // returns; rt's stack frame then unwinds
// all INSIDE one function whose caller is itself gc-framed.  ncc emits an
// auto-gc-roots epilogue (gc_stack_pop -> n00b_thread_self) at every framed
// function's exit.  Before the fix, after n00b_shutdown() returned, those
// epilogues dereferenced the now-dead runtime (n00b_default_runtime still
// pointed at the returned stack-local rt -> EXC_BAD_ACCESS), or tripped
// gc_stack_pop's frame-chain assert, because thread_self's identity had moved
// across the init/shutdown boundary.
//
// The fix: n00b_thread_init migrates the pre-init bootstrap gc-stack chain
// onto the registered main thread; n00b_shutdown migrates it back (main ->
// bootstrap) and clears n00b_default_runtime, so post-shutdown n00b_thread_self()
// resolves to the static bootstrap thread and the surviving caller frames pop
// cleanly off the bootstrap chain.
//
// This test replicates the pattern: a noinline gc-framed helper inits a
// stack-local runtime, does string work (exercising the gc-roots machinery),
// shuts down via the explicit-runtime _kargs form, and returns; main then
// returns.  Reaching exit 0 without crash/assert == fixed.
// ============================================================================

[[gnu::noinline]] static int
framed_command(void)
{
    n00b_runtime_t rt;
    char          *argv[] = {"test_shutdown_gc_stack", nullptr};
    n00b_init(&rt, 1, argv);

    // String work so the gc-roots epilogue has live frames to pop.
    n00b_string_t *s = n00b_string_from_cstr("policy");
    assert(s != nullptr && s->data != nullptr);
    int len = (int)s->u8_bytes;

    // Explicit-runtime form of the new _kargs n00b_shutdown.  After this
    // returns, framed_command's own gc_stack_pop epilogue runs with the
    // runtime already torn down.
    n00b_shutdown(.runtime = &rt);
    return len;
}

int
main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    // main is itself gc-framed; its epilogue pop also runs after shutdown.
    int len = framed_command();

    // libc-only past this point (no live runtime).  If we got here, both
    // framed_command's and main's post-shutdown gc_stack_pop epilogues
    // unwound without dereferencing the dead runtime.
    assert(len == 6); // "policy"
    printf("  [PASS] shutdown_from_framed_command\n");
    printf("All shutdown_gc_stack tests passed.\n");
    return 0;
}
