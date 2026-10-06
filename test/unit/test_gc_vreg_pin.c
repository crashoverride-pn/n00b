// A thread the collector suspends while it holds a heap pointer only in a
// vector register, or only in the red zone below its stack pointer, must find
// that pointer still naming the object when it resumes.
//
// Each case parks a worker in an asm spin loop with the pointer in that one
// place and in no general-purpose register, collects from the main thread
// (which keeps the object reachable, so a copying collect moves it unless
// something pins it), then lets the worker read the pointer back.

#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/gc.h"
#include "core/runtime.h"
#include "core/thread.h"

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);       \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

// Keeps the pointer out of every general-purpose register and stack slot the
// worker has until the asm unmasks it into the place under test.
#define POINTER_MASK 0xA5A5A5A5A5A5A5A5ULL
#define BOX_MAGIC    0x0B0E5EEDULL

typedef struct {
    uint64_t magic;
    uint64_t pad[7];
} box_t;

static _Atomic uint64_t masked_ptr;
static _Atomic int      ready;
static _Atomic int      go;
static _Atomic uint64_t seen;

static void *
hold_in_vector_register(void *arg)
{
    (void)arg;
    uint64_t m = atomic_load(&masked_ptr);
    uint64_t out;
#if defined(__aarch64__)
    __asm__ volatile("eor   x10, %[m], %[mask]\n"
                     "fmov  d16, x10\n"
                     "mov   x10, xzr\n"
                     "mov   w11, #1\n"
                     "stlr  w11, [%[ready]]\n"
                     "1:\n"
                     "ldar  w11, [%[go]]\n"
                     "cbz   w11, 1b\n"
                     "fmov  %[out], d16\n"
                     : [out] "=&r"(out)
                     : [m] "r"(m), [mask] "r"(POINTER_MASK), [ready] "r"(&ready), [go] "r"(&go)
                     : "x10", "x11", "v16", "memory");
#elif defined(__x86_64__)
    __asm__ volatile("movq  %[m], %%r10\n"
                     "xorq  %[mask], %%r10\n"
                     "movq  %%r10, %%xmm15\n"
                     "xorl  %%r10d, %%r10d\n"
                     "movl  $1, (%[ready])\n"
                     "1:\n"
                     "pause\n"
                     "movl  (%[go]), %%r11d\n"
                     "testl %%r11d, %%r11d\n"
                     "jz    1b\n"
                     "movq  %%xmm15, %[out]\n"
                     : [out] "=&r"(out)
                     : [m] "r"(m), [mask] "r"(POINTER_MASK), [ready] "r"(&ready), [go] "r"(&go)
                     : "r10", "r11", "xmm15", "memory");
#else
#error "test_gc_vreg_pin: add the asm for this architecture"
#endif
    atomic_store(&seen, out ^ POINTER_MASK);
    return nullptr;
}

#if (defined(__x86_64__) && !defined(_WIN32)) || (defined(__APPLE__) && defined(__aarch64__))
#define HAVE_RED_ZONE 1

static void *
hold_in_red_zone(void *arg)
{
    (void)arg;
    uint64_t m = atomic_load(&masked_ptr);
    uint64_t out;
#if defined(__aarch64__)
    __asm__ volatile("eor   x10, %[m], %[mask]\n"
                     "str   x10, [sp, #-16]\n"
                     "mov   x10, xzr\n"
                     "mov   w11, #1\n"
                     "stlr  w11, [%[ready]]\n"
                     "1:\n"
                     "ldar  w11, [%[go]]\n"
                     "cbz   w11, 1b\n"
                     "ldr   %[out], [sp, #-16]\n"
                     : [out] "=&r"(out)
                     : [m] "r"(m), [mask] "r"(POINTER_MASK), [ready] "r"(&ready), [go] "r"(&go)
                     : "x10", "x11", "memory");
#else
    __asm__ volatile("movq  %[m], %%r10\n"
                     "xorq  %[mask], %%r10\n"
                     "movq  %%r10, -16(%%rsp)\n"
                     "xorl  %%r10d, %%r10d\n"
                     "movl  $1, (%[ready])\n"
                     "1:\n"
                     "pause\n"
                     "movl  (%[go]), %%r11d\n"
                     "testl %%r11d, %%r11d\n"
                     "jz    1b\n"
                     "movq  -16(%%rsp), %[out]\n"
                     : [out] "=&r"(out)
                     : [m] "r"(m), [mask] "r"(POINTER_MASK), [ready] "r"(&ready), [go] "r"(&go)
                     : "r10", "r11", "memory");
#endif
    atomic_store(&seen, out ^ POINTER_MASK);
    return nullptr;
}
#endif

// Runs `holder` on a worker that keeps the object's address in the place under
// test while the main thread collects, and returns whether the worker's copy
// still names the object afterwards.
static bool
held_pointer_survives(void *(*holder)(void *))
{
    n00b_arena_t  *arena = n00b_new_arena(.size = 1 << 16, .use_gc = true);
    box_t *volatile obj  = n00b_alloc_with_opts(box_t,
                                               &(n00b_alloc_opts_t){
                                                   .allocator = (n00b_allocator_t *)arena,
                                               });
    obj->magic = BOX_MAGIC;

    atomic_store(&masked_ptr, (uint64_t)obj ^ POINTER_MASK);
    atomic_store(&ready, 0);
    atomic_store(&go, 0);
    atomic_store(&seen, 0);

    auto result = n00b_thread_spawn(holder, nullptr);
    REQUIRE(n00b_result_is_ok(result));
    n00b_thread_t *thread = n00b_result_get(result);

    while (atomic_load(&ready) == 0) {
    }

    // The worker is spinning, so the collector suspends it preemptively.
    n00b_collect(arena);

    atomic_store(&go, 1);
    n00b_thread_join(thread);

    REQUIRE(obj->magic == BOX_MAGIC);
    return (atomic_load(&seen) ^ POINTER_MASK) == (uint64_t)obj;
}

int
main(int argc, char **argv)
{
    // Copying collection: a pointer the collector misses goes stale.
    setenv("N00B_GC_PIN_ALL", "0", 1);

    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    REQUIRE(held_pointer_survives(hold_in_vector_register));
    printf("  [PASS] pointer held in a vector register\n");

#if defined(HAVE_RED_ZONE)
    REQUIRE(held_pointer_survives(hold_in_red_zone));
    printf("  [PASS] pointer held in the red zone\n");
#endif

    n00b_shutdown();
    return 0;
}
