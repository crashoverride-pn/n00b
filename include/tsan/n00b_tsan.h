/*
 * n00b's own race detector.
 *
 * The compiler instruments n00b with `-fsanitize=thread`, which emits calls to
 * the `__tsan_*` ABI on every memory access, atomic and function boundary.  We
 * implement that ABI ourselves and never link libclang_rt.tsan.  Two properties
 * of n00b make the stock runtime unusable and this one straightforward:
 *
 *   threads   n00b workers are Mach `thread_create` / raw `clone` threads.  The
 *             stock runtime allocates its per-thread state inside its
 *             `pthread_create` interceptor, so a n00b worker reaches
 *             instrumented code with a null thread state and the runtime
 *             CHECK-fails on its first access.  We register a thread where it
 *             is really born, in n00b_thread_launcher.
 *
 *   locks     n00b synchronizes on futexes and raw atomics, not on pthread
 *             mutexes.  The stock runtime infers happens-before from the
 *             pthread calls it intercepts and would therefore see none of ours,
 *             reporting every lock-protected access as a race.  Our locks call
 *             n00b_tsan_release / n00b_tsan_acquire directly.
 *
 * The detector is FastTrack-shaped: a per-thread vector clock, a vector clock
 * per sync object, and a small set of shadow cells per 8-byte granule recording
 * who touched it and when.
 *
 * Everything under src/tsan is compiled WITHOUT instrumentation (its own meson
 * static_library), so the detector never re-enters itself.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(N00B_TSAN)

// Dense thread slots.  A slot is reused after its thread dies; the epoch keeps
// climbing across the reuse so shadow written by the previous occupant stays
// correctly ordered against the new one.
#define N00B_TSAN_MAX_THREADS 1024

// Shadow cells retained per 8-byte granule.  More cells remember more distinct
// prior accesses and so catch more races, at 8 bytes of shadow each.
#ifndef N00B_TSAN_SHADOW_CELLS
#define N00B_TSAN_SHADOW_CELLS 4
#endif

// Frames retained per thread for reporting.  Deeper stacks keep the innermost
// frames and drop the rest.
#define N00B_TSAN_STACK_DEPTH 64

// Shadow is mapped per 2 MiB of application address space, found through a
// lock-free hash rather than a fixed arithmetic map.  A fixed map would have to
// reserve a large contiguous range and force n00b's own mmap allocator around
// it, which is what makes the stock runtime's layout unusable here.
#define N00B_TSAN_REGION_SHIFT 21
#define N00B_TSAN_REGION_SIZE  (UINT64_C(1) << N00B_TSAN_REGION_SHIFT)
#define N00B_TSAN_REGION_MASK  (N00B_TSAN_REGION_SIZE - 1)

typedef struct n00b_thread_t n00b_thread_t;

/*
 * A shadow cell, one 8-byte granule's record of a single past access.
 *
 *   [63:52] tid        owning thread slot
 *   [51:10] epoch      that thread's clock at the access
 *   [ 9: 2] byte mask  which of the granule's 8 bytes were touched
 *   [    1] is_write
 *   [    0] is_atomic
 *
 * A zero cell is empty, which is why epoch numbering starts at 1.
 */
typedef uint64_t n00b_tsan_cell_t;

#define N00B_TSAN_CELL_TID(c)    ((uint32_t)((c) >> 52))
#define N00B_TSAN_CELL_EPOCH(c)  (((c) >> 10) & UINT64_C(0x3ffffffffff))
#define N00B_TSAN_CELL_MASK(c)   ((uint8_t)(((c) >> 2) & 0xff))
#define N00B_TSAN_CELL_WRITE(c)  (((c) >> 1) & 1)
#define N00B_TSAN_CELL_ATOMIC(c) ((c) & 1)

#define N00B_TSAN_CELL_MAKE(tid, epoch, mask, wr, at)                          \
    (((uint64_t)(tid) << 52) | (((uint64_t)(epoch) & UINT64_C(0x3ffffffffff))  \
                                << 10)                                         \
     | ((uint64_t)(mask) << 2) | ((uint64_t)(wr) << 1) | (uint64_t)(at))

// Per-thread detector state.  Reached on every instrumented access, so the
// layout puts the hot fields first.
typedef struct n00b_tsan_thread_s {
    uint64_t  epoch;
    uint32_t  tid;
    int32_t   ignore_depth;
    uint64_t *vc;
    // Last shadow region this thread touched. Accesses cluster hard, so this
    // one compare removes the region hash from almost every access.
    uintptr_t shadow_cache_base;
    void     *shadow_cache_cells;
    // Bumped whenever this thread's clock changes, by its own epoch or by an
    // acquire. A sync object remembers the version it last saw from us, so a
    // release that would republish an unchanged clock costs one compare.
    uint64_t  vc_version;
    uint64_t  live;
    uint64_t  n_reads;
    uint64_t  n_writes;
    // Shadow call stack maintained by __tsan_func_entry/exit, so a report can
    // name where an access came from without a frame walk.
    uint32_t  stack_len;
    void     *stack[N00B_TSAN_STACK_DEPTH];
} n00b_tsan_thread_t;

// Lifecycle.  n00b_tsan_init runs from n00b_init before any worker exists.
extern void n00b_tsan_init(void);
extern void n00b_tsan_fini(void);

// Thread lifecycle.  The edges are carried by tokens rather than by thread
// structs: the spawner publishes its clock on the bundle it hands the new
// thread (`create_token`), and a thread publishes its final clock on its own
// handle (`join_token`) for whoever joins it.
extern n00b_tsan_thread_t *n00b_tsan_thread_start(void *create_token);
extern void                n00b_tsan_thread_finish(void *join_token);
extern void                n00b_tsan_thread_join(void *join_token);
extern void                n00b_tsan_thread_spawning(void *create_token);

// The current thread's detector state, or null before it is registered.
extern n00b_tsan_thread_t *n00b_tsan_self(void);

// Happens-before edges.  `release` publishes this thread's clock onto the sync
// object at `addr`; `acquire` folds that object's clock into this thread's.
// `acquire_release` is the read-modify-write pair for a lock that both ends an
// earlier critical section and begins a new one.
extern void n00b_tsan_acquire(void *addr);
extern void n00b_tsan_release(void *addr);
extern void n00b_tsan_release_merge(void *addr);
extern void n00b_tsan_sync_forget(void *addr);

// Lock annotations.  These carry the same information as acquire/release plus
// the lock identity used in reports.
extern void n00b_tsan_mutex_create(void *addr, bool is_rw);
extern void n00b_tsan_mutex_destroy(void *addr);
extern void n00b_tsan_mutex_acquired(void *addr, bool write_lock);
extern void n00b_tsan_mutex_releasing(void *addr, bool write_lock);

// Suppress checking on the current thread.  The GC, the allocator and any
// deliberate benign race sit inside a pair of these.
extern void n00b_tsan_ignore_begin(void);
extern void n00b_tsan_ignore_end(void);

// Stop-the-world brackets.  Nothing else runs between them, so all checking is
// suppressed and every thread's clock is advanced past the pause.
extern void n00b_tsan_stw_begin(void);
extern void n00b_tsan_stw_end(void);

// Memory lifecycle.  Freed or recycled memory must drop its shadow, otherwise
// the next owner of those bytes inherits the previous owner's access history
// and races are reported against a thread that no longer has anything to do
// with them.
extern void n00b_tsan_mem_reset(void *addr, size_t size);
extern void n00b_tsan_mem_release(void *addr, size_t size);

extern void n00b_tsan_report_summary(void);
extern uint64_t n00b_tsan_race_count(void);

#define N00B_TSAN_ACQUIRE(addr)        n00b_tsan_acquire(addr)
#define N00B_TSAN_RELEASE(addr)        n00b_tsan_release(addr)
#define N00B_TSAN_MUTEX_CREATE(a, rw)  n00b_tsan_mutex_create(a, rw)
#define N00B_TSAN_MUTEX_DESTROY(a)     n00b_tsan_mutex_destroy(a)
#define N00B_TSAN_MUTEX_ACQUIRED(a, w) n00b_tsan_mutex_acquired(a, w)
#define N00B_TSAN_MUTEX_RELEASING(a, w) n00b_tsan_mutex_releasing(a, w)
#define N00B_TSAN_IGNORE_BEGIN()       n00b_tsan_ignore_begin()
#define N00B_TSAN_IGNORE_END()         n00b_tsan_ignore_end()
#define N00B_TSAN_MEM_RESET(a, n)      n00b_tsan_mem_reset(a, n)
#define N00B_TSAN_MEM_RELEASE(a, n)    n00b_tsan_mem_release(a, n)
#define N00B_TSAN_INIT()               n00b_tsan_init()
#define N00B_TSAN_THREAD_START(tok)    n00b_tsan_thread_start(tok)
#define N00B_TSAN_THREAD_FINISH(tok)   n00b_tsan_thread_finish(tok)
#define N00B_TSAN_SPAWNING(tok)        n00b_tsan_thread_spawning(tok)
#define N00B_TSAN_JOIN(tok)            n00b_tsan_thread_join(tok)
#define N00B_TSAN_STW_BEGIN()          n00b_tsan_stw_begin()
#define N00B_TSAN_STW_END()            n00b_tsan_stw_end()

#else // !N00B_TSAN

#define N00B_TSAN_ACQUIRE(addr)         ((void)0)
#define N00B_TSAN_RELEASE(addr)         ((void)0)
#define N00B_TSAN_MUTEX_CREATE(a, rw)   ((void)0)
#define N00B_TSAN_MUTEX_DESTROY(a)      ((void)0)
#define N00B_TSAN_MUTEX_ACQUIRED(a, w)  ((void)0)
#define N00B_TSAN_MUTEX_RELEASING(a, w) ((void)0)
#define N00B_TSAN_IGNORE_BEGIN()        ((void)0)
#define N00B_TSAN_IGNORE_END()          ((void)0)
#define N00B_TSAN_MEM_RESET(a, n)       ((void)0)
#define N00B_TSAN_MEM_RELEASE(a, n)     ((void)0)
#define N00B_TSAN_INIT()                ((void)0)
#define N00B_TSAN_THREAD_START(tok)     ((void)0)
#define N00B_TSAN_THREAD_FINISH(tok)    ((void)0)
#define N00B_TSAN_SPAWNING(tok)         ((void)0)
#define N00B_TSAN_JOIN(tok)             ((void)0)
#define N00B_TSAN_STW_BEGIN()           ((void)0)
#define N00B_TSAN_STW_END()             ((void)0)

#endif
