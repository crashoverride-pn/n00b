#include <assert.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
// This test exercises the GC-stack setjmp/longjmp ABI directly
// (n00b_jmp_buf_t, n00b_setjmp/n00b_longjmp, n00b_gc_stack_frame_t). That ABI
// lives in core/codegen_abi_inject.h, which is intentionally NOT force-included
// anymore (decoupled for incremental compilation); include it explicitly here.
#include "core/codegen_abi_inject.h"

static n00b_runtime_t        test_runtime;
static n00b_gc_stack_frame_t *saved_top;
static n00b_gc_stack_frame_t *inner_top;

[[gnu::noinline]] static void
jump_inner(n00b_jmp_buf_t *ctx)
{
    void *inner_root = ctx;

    assert(inner_root != nullptr);
    inner_top = n00b_thread_self()->gc_stack_top;
    assert(inner_top != nullptr);
    assert(inner_top != ctx->n00b_gc_stack_top);

    n00b_longjmp(ctx, 17);
}

[[gnu::noinline]] static void
test_supported_nonlocal_exit_restores_stack_top(void)
{
    n00b_jmp_buf_t ctx        = {};
    void          *outer_root = &ctx;

    int value = n00b_setjmp(&ctx);
    if (!value) {
        assert(outer_root != nullptr);
        saved_top = ctx.n00b_gc_stack_top;
        assert(saved_top != nullptr);
        assert(n00b_thread_self()->gc_stack_top == saved_top);

        jump_inner(&ctx);
        assert(false);
    }

    assert(value == 17);
    assert(saved_top != nullptr);
    assert(inner_top != nullptr);
    assert(inner_top != saved_top);
    assert(n00b_thread_self()->gc_stack_top == saved_top);
}

int
main(void)
{
    n00b_init(&test_runtime, 0, nullptr);

    test_supported_nonlocal_exit_restores_stack_top();

    n00b_shutdown();
    return 0;
}
