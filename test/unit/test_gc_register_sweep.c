// Every place a suspended thread can hold a heap pointer must keep that
// pointer naming its object across a copying collection: each general-purpose
// register the ABI lets code use, each 64-bit lane of each vector register,
// and each word of the red zone below the stack pointer.
//
// Each case parks a worker in an asm spin loop with the pointer in exactly one
// of those places, collects from the main thread (which keeps the object
// reachable, so a copying collect moves it unless something pins it), then
// lets the worker read the pointer back. Every case runs, and every one that
// comes back stale is named before the test fails.

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

// Keeps the pointer out of every register and stack slot the worker has until
// the asm unmasks it into the place under test.
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

// A call after the asm keeps every holder out of leaf-function codegen, so the
// compiler keeps nothing of its own in the red zone the asm writes to.
__attribute__((noinline)) static void
report(uint64_t out)
{
    atomic_store(&seen, out ^ POINTER_MASK);
}

#define HOLDER_OPERANDS                                                        \
    : [out] "=&r"(out), [t] "=&r"(t)                                           \
    : [m] "r"(m), [mask] "r"(POINTER_MASK), [ready] "r"(&ready), [go] "r"(&go)

#if defined(__aarch64__)

#define SPIN                                                                   \
    "mov   %w[t], #1\n"                                                        \
    "stlr  %w[t], [%[ready]]\n"                                                \
    "1:\n"                                                                     \
    "ldar  %w[t], [%[go]]\n"                                                   \
    "cbz   %w[t], 1b\n"

#define HOLD_GPR(r)                                                            \
    static void *hold_##r(void *arg)                                           \
    {                                                                          \
        (void)arg;                                                             \
        uint64_t m = atomic_load(&masked_ptr);                                 \
        uint64_t out, t;                                                       \
        __asm__ volatile("eor   " #r ", %[m], %[mask]\n" SPIN                  \
                         "mov   %[out], " #r "\n" HOLDER_OPERANDS              \
                         : #r, "memory");                                      \
        report(out);                                                           \
        return nullptr;                                                        \
    }

#define HOLD_VLANE(n, lane)                                                    \
    static void *hold_v##n##_##lane(void *arg)                                 \
    {                                                                          \
        (void)arg;                                                             \
        uint64_t m = atomic_load(&masked_ptr);                                 \
        uint64_t out, t;                                                       \
        __asm__ volatile("eor   %[t], %[m], %[mask]\n"                         \
                         "movi  v" #n ".16b, #0\n"                             \
                         "mov   v" #n ".d[" #lane "], %[t]\n" SPIN             \
                         "mov   %[out], v" #n ".d[" #lane "]\n"                \
                         HOLDER_OPERANDS                                       \
                         : "v" #n, "memory");                                  \
        report(out);                                                           \
        return nullptr;                                                        \
    }

#define HOLD_V(n) HOLD_VLANE(n, 0) HOLD_VLANE(n, 1)

// x18 is the platform register, and x29 and x30 are the frame pointer and
// link register, none of which inline asm may clobber.
#define FOR_EACH_GPR(X)                                                        \
    X(x0) X(x1) X(x2) X(x3) X(x4) X(x5) X(x6) X(x7) X(x8) X(x9) X(x10)         \
    X(x11) X(x12) X(x13) X(x14) X(x15) X(x16) X(x17) X(x19) X(x20) X(x21)      \
    X(x22) X(x23) X(x24) X(x25) X(x26) X(x27) X(x28)

#define FOR_EACH_VREG(X)                                                       \
    X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7) X(8) X(9) X(10) X(11) X(12)        \
    X(13) X(14) X(15) X(16) X(17) X(18) X(19) X(20) X(21) X(22) X(23) X(24)    \
    X(25) X(26) X(27) X(28) X(29) X(30) X(31)

#elif defined(__x86_64__)

#define SPIN                                                                   \
    "movl  $1, (%[ready])\n"                                                   \
    "1:\n"                                                                     \
    "pause\n"                                                                  \
    "movl  (%[go]), %k[t]\n"                                                   \
    "testl %k[t], %k[t]\n"                                                     \
    "jz    1b\n"

#define HOLD_GPR(r)                                                            \
    static void *hold_##r(void *arg)                                           \
    {                                                                          \
        (void)arg;                                                             \
        uint64_t m = atomic_load(&masked_ptr);                                 \
        uint64_t out, t;                                                       \
        __asm__ volatile("movq  %[m], %%" #r "\n"                              \
                         "xorq  %[mask], %%" #r "\n" SPIN                      \
                         "movq  %%" #r ", %[out]\n" HOLDER_OPERANDS            \
                         : #r, "memory");                                      \
        report(out);                                                           \
        return nullptr;                                                        \
    }

// Lanes 0 and 1 are the xmm half, set with SSE2. Lanes 2 and 3 are the ymm
// upper half: vpermq moves lane 0 to the lane under test and fills the rest
// from the zero lane 1.
#define HOLD_VLANE(n, lane, put, get)                                          \
    static void *hold_v##n##_##lane(void *arg)                                 \
    {                                                                          \
        (void)arg;                                                             \
        uint64_t m = atomic_load(&masked_ptr);                                 \
        uint64_t out, t;                                                       \
        __asm__ volatile("movq  %[m], %[t]\n"                                  \
                         "xorq  %[mask], %[t]\n" put SPIN get                  \
                         HOLDER_OPERANDS                                       \
                         : "xmm" #n, "memory");                                \
        report(out);                                                           \
        return nullptr;                                                        \
    }

#define HOLD_V(n)                                                              \
    HOLD_VLANE(n, 0, "movq  %[t], %%xmm" #n "\n",                              \
               "movq  %%xmm" #n ", %[out]\n")                                  \
    HOLD_VLANE(n, 1,                                                           \
               "movq  %[t], %%xmm" #n "\n"                                     \
               "pslldq $8, %%xmm" #n "\n",                                     \
               "psrldq $8, %%xmm" #n "\n"                                      \
               "movq  %%xmm" #n ", %[out]\n")                                  \
    HOLD_VLANE(n, 2,                                                           \
               "vmovq %[t], %%xmm" #n "\n"                                     \
               "vpermq $0x45, %%ymm" #n ", %%ymm" #n "\n",                     \
               "vpermq $0x02, %%ymm" #n ", %%ymm" #n "\n"                      \
               "vmovq %%xmm" #n ", %[out]\n"                                   \
               "vzeroupper\n")                                                 \
    HOLD_VLANE(n, 3,                                                           \
               "vmovq %[t], %%xmm" #n "\n"                                     \
               "vpermq $0x15, %%ymm" #n ", %%ymm" #n "\n",                     \
               "vpermq $0x03, %%ymm" #n ", %%ymm" #n "\n"                      \
               "vmovq %%xmm" #n ", %[out]\n"                                   \
               "vzeroupper\n")

// rsp and rbp are the stack and frame pointers.
#define FOR_EACH_GPR(X)                                                        \
    X(rax) X(rbx) X(rcx) X(rdx) X(rsi) X(rdi) X(r8) X(r9) X(r10) X(r11)        \
    X(r12) X(r13) X(r14) X(r15)

#define FOR_EACH_VREG(X)                                                       \
    X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7) X(8) X(9) X(10) X(11) X(12)        \
    X(13) X(14) X(15)

#else
#error "test_gc_register_sweep: add the asm for this architecture"
#endif

FOR_EACH_GPR(HOLD_GPR)
FOR_EACH_VREG(HOLD_V)

#if (defined(__x86_64__) && !defined(_WIN32)) || (defined(__APPLE__) && defined(__aarch64__))
#define HAVE_RED_ZONE 1

#if defined(__aarch64__)
#define HOLD_RED_ZONE(off)                                                     \
    static void *hold_rz_##off(void *arg)                                      \
    {                                                                          \
        (void)arg;                                                             \
        uint64_t m = atomic_load(&masked_ptr);                                 \
        uint64_t out, t;                                                       \
        __asm__ volatile("eor   %[t], %[m], %[mask]\n"                         \
                         "stur  %[t], [sp, #-" #off "]\n" SPIN                 \
                         "ldur  %[out], [sp, #-" #off "]\n" HOLDER_OPERANDS    \
                         : "memory");                                          \
        report(out);                                                           \
        return nullptr;                                                        \
    }
#else
#define HOLD_RED_ZONE(off)                                                     \
    static void *hold_rz_##off(void *arg)                                      \
    {                                                                          \
        (void)arg;                                                             \
        uint64_t m = atomic_load(&masked_ptr);                                 \
        uint64_t out, t;                                                       \
        __asm__ volatile("movq  %[m], %[t]\n"                                  \
                         "xorq  %[mask], %[t]\n"                               \
                         "movq  %[t], -" #off "(%%rsp)\n" SPIN                 \
                         "movq  -" #off "(%%rsp), %[out]\n" HOLDER_OPERANDS    \
                         : "memory");                                          \
        report(out);                                                           \
        return nullptr;                                                        \
    }
#endif

// Both ABIs reserve 128 bytes below the stack pointer.
#define FOR_EACH_RED_ZONE_OFFSET(X)                                            \
    X(8) X(16) X(24) X(32) X(40) X(48) X(56) X(64) X(72) X(80) X(88) X(96)     \
    X(104) X(112) X(120) X(128)

FOR_EACH_RED_ZONE_OFFSET(HOLD_RED_ZONE)
#endif

typedef struct {
    const char *name;
    void *(*holder)(void *);
    bool        needs_avx2;
} place_t;

#define GPR_PLACE(r) {#r, hold_##r, false},
#if defined(__x86_64__)
#define VREG_PLACE(n)                                                          \
    {"v" #n " lane 0", hold_v##n##_0, false},                                  \
    {"v" #n " lane 1", hold_v##n##_1, false},                                  \
    {"v" #n " lane 2", hold_v##n##_2, true},                                   \
    {"v" #n " lane 3", hold_v##n##_3, true},
#else
#define VREG_PLACE(n)                                                          \
    {"v" #n " lane 0", hold_v##n##_0, false},                                  \
    {"v" #n " lane 1", hold_v##n##_1, false},
#endif
#define RED_ZONE_PLACE(off) {"red zone sp-" #off, hold_rz_##off, false},

static const place_t places[] = {
    FOR_EACH_GPR(GPR_PLACE)
    FOR_EACH_VREG(VREG_PLACE)
#if defined(HAVE_RED_ZONE)
    FOR_EACH_RED_ZONE_OFFSET(RED_ZONE_PLACE)
#endif
};

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

#if defined(__x86_64__)
    bool have_avx2 = __builtin_cpu_supports("avx2");
#else
    bool have_avx2 = false;
#endif

    int ran   = 0;
    int stale = 0;
    for (size_t i = 0; i < sizeof(places) / sizeof(places[0]); i++) {
        if (places[i].needs_avx2 && !have_avx2) {
            continue;
        }
        ran++;
        if (!held_pointer_survives(places[i].holder)) {
            fprintf(stderr, "  [FAIL] pointer held in %s went stale\n", places[i].name);
            stale++;
        }
    }

    printf("  %d places, %d stale\n", ran, stale);
    REQUIRE(stale == 0);
    printf("  [PASS] pointer held in every register, lane, and red-zone word\n");

    n00b_shutdown();
    return 0;
}
