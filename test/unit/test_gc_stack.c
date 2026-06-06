#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/gc.h"
#include "core/gc_stack.h"
#include "core/runtime.h"
#include "core/stw.h"
#include "core/thread.h"
#include "core/atomic.h"

#define ARENA_OPTS(a)                                                                          \
    &(n00b_alloc_opts_t)                                                                       \
    {                                                                                          \
        .allocator = (n00b_allocator_t *)(a)                                                   \
    }

#define PTR_SAVE_MASK UINT64_C(0xa5a5a5a5a5a5a5a5)

typedef struct {
    uint64_t value;
    void    *next;
} exact_target_t;

typedef struct {
    n00b_arena_t     *arena;
    _Atomic uint32_t  stage;
    uintptr_t         before_xor;
    uintptr_t         after;
    uint64_t          value;
} fallback_worker_ctx_t;

enum {
    FALLBACK_WORKER_INIT = 0,
    FALLBACK_WORKER_READY,
    FALLBACK_WORKER_RELEASE,
};

static const n00b_gc_stack_slot_t one_root_slots[] = {
    {.root_index = 0, .num_words = 1},
};

static const n00b_gc_stack_map_t one_root_map = {
    .num_roots     = 1,
    .num_slots     = 1,
    .slots         = one_root_slots,
    .function_name = "one_root",
    .file_name     = __FILE__,
};

static __attribute__((noinline)) void
test_exact_only_declared_roots_inner(n00b_arena_t *arena)
{
    exact_target_t *live = n00b_alloc_with_opts(exact_target_t, ARENA_OPTS(arena));
    live->value          = 0xABCD0001ULL;

    volatile exact_target_t *dead   = n00b_alloc_with_opts(exact_target_t, ARENA_OPTS(arena));
    ((exact_target_t *)dead)->value = 0xDEAD0001ULL;

    uintptr_t live_before = (uintptr_t)live;
    uintptr_t dead_before = (uintptr_t)dead;

    void                  *roots[] = {&live};
    n00b_gc_stack_frame_t  frame;
    n00b_gc_stack_policy_t old_policy = n00b_gc_stack_set_policy(N00B_GC_STACK_EXACT_ONLY);

    n00b_gc_stack_push(&frame, &one_root_map, roots);
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();
    n00b_gc_stack_pop(&frame);
    n00b_gc_stack_set_policy(old_policy);

    assert((uintptr_t)live != live_before);
    assert(live->value == 0xABCD0001ULL);
    assert((uintptr_t)dead == dead_before);
}

static void
test_exact_only_declared_roots(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    test_exact_only_declared_roots_inner(arena);
    printf("  [PASS] exact_only_declared_roots\n");
}

static __attribute__((noinline)) void
test_exact_only_nested_frames_collect(n00b_arena_t    *arena,
                                      exact_target_t **outer_slot,
                                      uintptr_t        outer_before)
{
    exact_target_t *inner = n00b_alloc_with_opts(exact_target_t, ARENA_OPTS(arena));

    inner->value = 0xABCD0003ULL;

    uintptr_t inner_before = (uintptr_t)inner;

    void                 *roots[] = {&inner};
    n00b_gc_stack_frame_t frame;

    n00b_gc_stack_push(&frame, &one_root_map, roots);
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();
    n00b_gc_stack_pop(&frame);

    assert((uintptr_t)*outer_slot != outer_before);
    assert((uintptr_t)inner != inner_before);
    assert((*outer_slot)->value == 0xABCD0002ULL);
    assert(inner->value == 0xABCD0003ULL);
}

static __attribute__((noinline)) void
test_exact_only_nested_frames_inner(n00b_arena_t *arena)
{
    exact_target_t *outer = n00b_alloc_with_opts(exact_target_t, ARENA_OPTS(arena));

    outer->value = 0xABCD0002ULL;

    uintptr_t outer_before = (uintptr_t)outer;

    void                  *roots[] = {&outer};
    n00b_gc_stack_frame_t  frame;
    n00b_gc_stack_policy_t old_policy = n00b_gc_stack_set_policy(N00B_GC_STACK_EXACT_ONLY);

    n00b_gc_stack_push(&frame, &one_root_map, roots);
    test_exact_only_nested_frames_collect(arena, &outer, outer_before);
    n00b_gc_stack_pop(&frame);
    n00b_gc_stack_set_policy(old_policy);

    assert((uintptr_t)outer != outer_before);
    assert(outer->value == 0xABCD0002ULL);
}

static void
test_exact_only_nested_frames(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    test_exact_only_nested_frames_inner(arena);
    printf("  [PASS] exact_only_nested_frames\n");
}

static void *
fallback_no_frame_worker(void *arg)
{
    // Mention the manual GC-stack API so ncc does not auto-publish an exact
    // frame for this worker; this test intentionally exercises fallback
    // conservative scanning when no exact frame is active.
    if (false) {
        n00b_gc_stack_pop((n00b_gc_stack_frame_t *)nullptr);
    }

    fallback_worker_ctx_t *ctx = arg;
    exact_target_t        *live = n00b_alloc_with_opts(exact_target_t,
                                                       ARENA_OPTS(ctx->arena));

    live->value = 0xABCD0004ULL;

    uintptr_t         live_before    = (uintptr_t)live;
    volatile uint64_t stack_words[8] = {0};

    ctx->before_xor = live_before ^ PTR_SAVE_MASK;
    stack_words[3]  = live_before;

    n00b_gc_stack_policy_t old_policy =
        n00b_gc_stack_set_policy(N00B_GC_STACK_EXACT_WITH_FALLBACK);

    atomic_store(&ctx->stage, FALLBACK_WORKER_READY);

    while (atomic_load(&ctx->stage) == FALLBACK_WORKER_READY) {
    }

    ctx->after = stack_words[3];
    if (ctx->after != (ctx->before_xor ^ PTR_SAVE_MASK)) {
        ctx->value = ((exact_target_t *)(uintptr_t)ctx->after)->value;
    }

    n00b_gc_stack_set_policy(old_policy);

    return nullptr;
}

static void
test_exact_with_fallback_no_frame(void)
{
    n00b_arena_t          *arena = n00b_new_arena(.size = 4096, .use_gc = true);
    fallback_worker_ctx_t  ctx   = {.arena = arena};

    auto result = n00b_thread_spawn(fallback_no_frame_worker, &ctx);
    assert(n00b_result_is_ok(result));
    n00b_thread_t *thread = n00b_result_get(result);

    while (atomic_load(&ctx.stage) != FALLBACK_WORKER_READY) {
    }

    n00b_stop_the_world();
    n00b_collect(arena);
    atomic_store(&ctx.stage, FALLBACK_WORKER_RELEASE);
    n00b_restart_the_world();

    n00b_thread_join(thread);

    uintptr_t before = ctx.before_xor ^ PTR_SAVE_MASK;

    assert(ctx.after != before);
    assert(ctx.value == 0xABCD0004ULL);
    printf("  [PASS] exact_with_fallback_no_frame\n");
}

static __attribute__((noinline)) void
test_exact_with_fallback_active_frame_inner(n00b_arena_t *arena)
{
    exact_target_t *live = n00b_alloc_with_opts(exact_target_t, ARENA_OPTS(arena));
    live->value          = 0xABCD0005ULL;

    exact_target_t *dead = n00b_alloc_with_opts(exact_target_t, ARENA_OPTS(arena));
    dead->value          = 0xDEAD0005ULL;

    uintptr_t         live_before = (uintptr_t)live;
    uintptr_t         dead_before = (uintptr_t)dead;
    volatile uint64_t stack_words[8] = {0};

    stack_words[3] = dead_before;

    void                  *roots[] = {&live};
    n00b_gc_stack_frame_t  frame;
    n00b_gc_stack_policy_t old_policy =
        n00b_gc_stack_set_policy(N00B_GC_STACK_EXACT_WITH_FALLBACK);

    n00b_gc_stack_push(&frame, &one_root_map, roots);
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();
    n00b_gc_stack_pop(&frame);
    n00b_gc_stack_set_policy(old_policy);

    assert((uintptr_t)live != live_before);
    assert(live->value == 0xABCD0005ULL);
    assert(stack_words[3] == dead_before);
}

static void
test_exact_with_fallback_active_frame(void)
{
    n00b_arena_t *arena = n00b_new_arena(.size = 4096, .use_gc = true);

    test_exact_with_fallback_active_frame_inner(arena);
    printf("  [PASS] exact_with_fallback_active_frame\n");
}

int
main(int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    printf("test_gc_stack:\n");
    test_exact_only_declared_roots();
    test_exact_only_nested_frames();
    test_exact_with_fallback_no_frame();
    test_exact_with_fallback_active_frame();
    printf("All GC stack tests passed.\n");

    n00b_shutdown();
    return 0;
}
