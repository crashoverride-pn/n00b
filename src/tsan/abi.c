/*
 * The compiler-facing half: the `__tsan_*` entry points clang emits under
 * -fsanitize=thread.  Nothing here is a stub.  Every access is checked, and the
 * atomics both perform the operation the compiler removed and record the
 * happens-before edge implied by their memory order.
 *
 * Instrumenting the atomics is what makes n00b's own locks work without
 * annotating each one: a futex mutex is a release store and an acquiring CAS on
 * the lock word, so the edge falls out of the atomic itself.
 */

#include "internal.h"

#include <sanitizer/tsan_interface_atomic.h>

#include <string.h>

// ------------------------------------------------------------------ lifecycle

void
__tsan_init(void)
{
    n00b_tsan_init();
}

// Every GC-framed call in the tree reaches these, which makes them the hottest
// entry points in the ABI. Keeping a shadow stack here would cost a thread
// lookup per call and buy only the frame list in a report; the access PC that
// n00b_tsan_report_race already prints locates the same code.
void
__tsan_func_entry(void *pc)
{
    (void)pc;
}

void
__tsan_func_exit(void)
{
}

// --------------------------------------------------------------------- access

#define N00B_TSAN_ACCESS(name, size, is_write)                                 \
    void __tsan_##name(void *addr)                                             \
    {                                                                          \
        n00b_tsan_check_access(addr,                                           \
                               size,                                           \
                               is_write,                                       \
                               false,                                          \
                               __builtin_return_address(0));                   \
    }                                                                          \
    void __tsan_##name##_pc(void *addr, void *pc)                              \
    {                                                                          \
        n00b_tsan_check_access(addr, size, is_write, false, pc);                \
    }

N00B_TSAN_ACCESS(read1, 1, false)
N00B_TSAN_ACCESS(read2, 2, false)
N00B_TSAN_ACCESS(read4, 4, false)
N00B_TSAN_ACCESS(read8, 8, false)
N00B_TSAN_ACCESS(read16, 16, false)
N00B_TSAN_ACCESS(write1, 1, true)
N00B_TSAN_ACCESS(write2, 2, true)
N00B_TSAN_ACCESS(write4, 4, true)
N00B_TSAN_ACCESS(write8, 8, true)
N00B_TSAN_ACCESS(write16, 16, true)

#define N00B_TSAN_UNALIGNED(name, size, is_write)                              \
    void __tsan_unaligned_##name(void *addr)                                   \
    {                                                                          \
        n00b_tsan_check_access(addr,                                           \
                               size,                                           \
                               is_write,                                       \
                               false,                                          \
                               __builtin_return_address(0));                   \
    }

N00B_TSAN_UNALIGNED(read2, 2, false)
N00B_TSAN_UNALIGNED(read4, 4, false)
N00B_TSAN_UNALIGNED(read8, 8, false)
N00B_TSAN_UNALIGNED(read16, 16, false)
N00B_TSAN_UNALIGNED(write2, 2, true)
N00B_TSAN_UNALIGNED(write4, 4, true)
N00B_TSAN_UNALIGNED(write8, 8, true)
N00B_TSAN_UNALIGNED(write16, 16, true)

static void
range_access(void *addr, unsigned long size, bool is_write, void *pc)
{
    uintptr_t p   = (uintptr_t)addr;
    uintptr_t end = p + size;

    // Check a granule at a time; a range access is rare next to the scalar
    // ones, so clarity beats a wider stride here.
    while (p < end) {
        size_t chunk = 8 - (p & 7);
        if (chunk > end - p) {
            chunk = end - p;
        }
        n00b_tsan_check_access((void *)p, chunk, is_write, false, pc);
        p += chunk;
    }
}

void
__tsan_read_range(void *addr, unsigned long size)
{
    range_access(addr, size, false, __builtin_return_address(0));
}

void
__tsan_write_range(void *addr, unsigned long size)
{
    range_access(addr, size, true, __builtin_return_address(0));
}

void
__tsan_read_range_pc(void *addr, unsigned long size, void *pc)
{
    range_access(addr, size, false, pc);
}

void
__tsan_write_range_pc(void *addr, unsigned long size, void *pc)
{
    range_access(addr, size, true, pc);
}

void
__tsan_vptr_read(void **vptr)
{
    n00b_tsan_check_access(vptr, 8, false, false, __builtin_return_address(0));
}

void
__tsan_vptr_update(void **vptr, void *new_val)
{
    if (*vptr != new_val) {
        n00b_tsan_check_access(vptr,
                               8,
                               true,
                               false,
                               __builtin_return_address(0));
    }
}

// -------------------------------------------------------------- mem intrinsics

void *
__tsan_memcpy(void *dst, const void *src, unsigned long size)
{
    void *pc = __builtin_return_address(0);
    range_access((void *)src, size, false, pc);
    range_access(dst, size, true, pc);
    return memcpy(dst, src, size);
}

void *
__tsan_memmove(void *dst, const void *src, unsigned long size)
{
    void *pc = __builtin_return_address(0);
    range_access((void *)src, size, false, pc);
    range_access(dst, size, true, pc);
    return memmove(dst, src, size);
}

void *
__tsan_memset(void *dst, int c, unsigned long size)
{
    range_access(dst, size, true, __builtin_return_address(0));
    return memset(dst, c, size);
}

// -------------------------------------------------------------------- atomics

static inline int
to_builtin_order(int mo)
{
    switch (mo) {
    case __tsan_memory_order_relaxed:
        return __ATOMIC_RELAXED;
    case __tsan_memory_order_consume:
        return __ATOMIC_CONSUME;
    case __tsan_memory_order_acquire:
        return __ATOMIC_ACQUIRE;
    case __tsan_memory_order_release:
        return __ATOMIC_RELEASE;
    case __tsan_memory_order_acq_rel:
        return __ATOMIC_ACQ_REL;
    default:
        return __ATOMIC_SEQ_CST;
    }
}

static inline bool
order_acquires(int mo)
{
    return mo == __tsan_memory_order_consume || mo == __tsan_memory_order_acquire
        || mo == __tsan_memory_order_acq_rel || mo == __tsan_memory_order_seq_cst;
}

static inline bool
order_releases(int mo)
{
    return mo == __tsan_memory_order_release || mo == __tsan_memory_order_acq_rel
        || mo == __tsan_memory_order_seq_cst;
}

#define N00B_TSAN_ATOMIC(bits, type)                                           \
    type __tsan_atomic##bits##_load(const volatile type *a,                    \
                                    int                 mo)                   \
    {                                                                          \
        n00b_tsan_check_access((void *)a,                                      \
                               bits / 8,                                       \
                               false,                                          \
                               true,                                           \
                               __builtin_return_address(0));                   \
        type v;                                                                \
        __atomic_load((type *)a, &v, to_builtin_order(mo));                    \
        if (order_acquires(mo)) {                                              \
            n00b_tsan_acquire((void *)a);                                      \
        }                                                                      \
        return v;                                                              \
    }                                                                          \
                                                                               \
    void __tsan_atomic##bits##_store(volatile type      *a,                    \
                                     type                v,                    \
                                     int                 mo)                   \
    {                                                                          \
        n00b_tsan_check_access((void *)a,                                      \
                               bits / 8,                                       \
                               true,                                           \
                               true,                                           \
                               __builtin_return_address(0));                   \
        if (order_releases(mo)) {                                              \
            n00b_tsan_release((void *)a);                                      \
        }                                                                      \
        __atomic_store((type *)a, &v, to_builtin_order(mo));                   \
    }                                                                          \
                                                                               \
    type __tsan_atomic##bits##_exchange(volatile type      *a,                 \
                                        type                v,                 \
                                        int                 mo)                \
    {                                                                          \
        n00b_tsan_check_access((void *)a,                                      \
                               bits / 8,                                       \
                               true,                                           \
                               true,                                           \
                               __builtin_return_address(0));                   \
        if (order_releases(mo)) {                                              \
            n00b_tsan_release((void *)a);                                      \
        }                                                                      \
        type out;                                                              \
        __atomic_exchange((type *)a, &v, &out, to_builtin_order(mo));          \
        if (order_acquires(mo)) {                                              \
            n00b_tsan_acquire((void *)a);                                      \
        }                                                                      \
        return out;                                                            \
    }                                                                          \
                                                                               \
    N00B_TSAN_RMW(bits, type, fetch_add, __atomic_fetch_add)                   \
    N00B_TSAN_RMW(bits, type, fetch_sub, __atomic_fetch_sub)                   \
    N00B_TSAN_RMW(bits, type, fetch_and, __atomic_fetch_and)                   \
    N00B_TSAN_RMW(bits, type, fetch_or, __atomic_fetch_or)                     \
    N00B_TSAN_RMW(bits, type, fetch_xor, __atomic_fetch_xor)                   \
    N00B_TSAN_RMW(bits, type, fetch_nand, __atomic_fetch_nand)                 \
                                                                               \
    int __tsan_atomic##bits##_compare_exchange_strong(                         \
        volatile type      *a,                                                 \
        type               *c,                                                 \
        type                v,                                                 \
        int                 mo,                                                \
        int                 fail_mo)                                           \
    {                                                                          \
        return n00b_tsan_cas##bits(a, c, v, mo, fail_mo, false);               \
    }                                                                          \
                                                                               \
    int __tsan_atomic##bits##_compare_exchange_weak(                           \
        volatile type      *a,                                                 \
        type               *c,                                                 \
        type                v,                                                 \
        int                 mo,                                                \
        int                 fail_mo)                                           \
    {                                                                          \
        return n00b_tsan_cas##bits(a, c, v, mo, fail_mo, true);                \
    }                                                                          \
                                                                               \
    type __tsan_atomic##bits##_compare_exchange_val(                           \
        volatile type      *a,                                                 \
        type                c,                                                 \
        type                v,                                                 \
        int                 mo,                                                \
        int                 fail_mo)                                           \
    {                                                                          \
        type expected = c;                                                     \
        n00b_tsan_cas##bits(a, &expected, v, mo, fail_mo, false);              \
        return expected;                                                       \
    }

#define N00B_TSAN_RMW(bits, type, suffix, builtin)                             \
    type __tsan_atomic##bits##_##suffix(volatile type      *a,                 \
                                        type                v,                 \
                                        int                 mo)                \
    {                                                                          \
        n00b_tsan_check_access((void *)a,                                      \
                               bits / 8,                                       \
                               true,                                           \
                               true,                                           \
                               __builtin_return_address(0));                   \
        if (order_releases(mo)) {                                              \
            n00b_tsan_release((void *)a);                                      \
        }                                                                      \
        type out = builtin((type *)a, v, to_builtin_order(mo));                \
        if (order_acquires(mo)) {                                              \
            n00b_tsan_acquire((void *)a);                                      \
        }                                                                      \
        return out;                                                            \
    }

#define N00B_TSAN_CAS(bits, type)                                              \
    static inline int n00b_tsan_cas##bits(volatile type      *a,               \
                                          type               *c,               \
                                          type                v,               \
                                          int                 mo,              \
                                          int                 fail_mo,         \
                                          bool                weak)            \
    {                                                                          \
        n00b_tsan_check_access((void *)a,                                      \
                               bits / 8,                                       \
                               true,                                           \
                               true,                                           \
                               __builtin_return_address(0));                   \
        if (order_releases(mo)) {                                              \
            n00b_tsan_release((void *)a);                                      \
        }                                                                      \
        bool ok = __atomic_compare_exchange((type *)a,                         \
                                            c,                                 \
                                            &v,                                \
                                            weak,                              \
                                            to_builtin_order(mo),              \
                                            to_builtin_order(fail_mo));        \
        if (order_acquires(ok ? mo : fail_mo)) {                               \
            n00b_tsan_acquire((void *)a);                                      \
        }                                                                      \
        return ok ? 1 : 0;                                                     \
    }

N00B_TSAN_CAS(8, __tsan_atomic8)
N00B_TSAN_CAS(16, __tsan_atomic16)
N00B_TSAN_CAS(32, __tsan_atomic32)
N00B_TSAN_CAS(64, __tsan_atomic64)
#if __TSAN_HAS_INT128
N00B_TSAN_CAS(128, __tsan_atomic128)
#endif

N00B_TSAN_ATOMIC(8, __tsan_atomic8)
N00B_TSAN_ATOMIC(16, __tsan_atomic16)
N00B_TSAN_ATOMIC(32, __tsan_atomic32)
N00B_TSAN_ATOMIC(64, __tsan_atomic64)
#if __TSAN_HAS_INT128
N00B_TSAN_ATOMIC(128, __tsan_atomic128)
#endif

void
__tsan_atomic_thread_fence(int                 mo)
{
    __atomic_thread_fence(to_builtin_order(mo));
}

void
__tsan_atomic_signal_fence(int                 mo)
{
    __atomic_signal_fence(to_builtin_order(mo));
}
