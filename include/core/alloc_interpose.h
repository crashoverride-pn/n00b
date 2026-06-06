#pragma once

/**
 * @file alloc_interpose.h
 * @brief libc malloc-family interposition routed through n00b's user pool.
 *
 * §11 ABI-shim boundary: the n00b_interposed_* entry points below DEFINE the
 * libc malloc family, so the libc-shaped signatures here (`char *` returns,
 * `const char *` params on strdup/strndup) are the C ABI they must match and
 * are allowed in this shim header only. Internal libn00b code uses the n00b
 * surface (n00b_alloc / n00b_string_t), never these.
 *
 * Vendored libraries (picoquic / picotls / their TLS backend) call the libc
 * malloc family directly.  On a raw n00b off-libc worker thread the first
 * libc malloc per thread builds a per-thread cache via pthread_self(), which
 * traps (macOS arm64 PAC on a minimal TCB).  To run that code on off-libc
 * workers we interpose the malloc family so every call lands in n00b's
 * non-moving, free-by-pointer @c user_pool instead of libc's allocator.
 *
 * Backing allocator: @c rt->user_pool (GC-visible, non-moving).  The pool's
 * per-entry size class lets realloc()/malloc_usable_size() recover sizes
 * with no side metadata (see @ref n00b_pool_usable_size).
 *
 * Lifecycle: interposition is live from process start, but the user pool
 * only exists after n00b_init.  Before the runtime is ready the shim
 * delegates to the real libc symbols (resolved via dlsym(RTLD_NEXT)); those
 * pre-init allocations run on the main thread with a full TCB, so libc is
 * safe there.  free()/realloc() resolve ownership by address so a pointer
 * handed out before init is freed back through libc, and a pool pointer is
 * freed back through the pool.
 *
 * Install mechanism is platform-specific:
 *   - macOS:   a `__DATA,__interpose` table that MUST live in the main
 *              executable — the user includes <n00b/alloc_interpose.h> from
 *              their main translation unit.
 *   - Linux:   strong `malloc`/`free`/... symbols defined in libn00b
 *              override libc's (no user action beyond linking libn00b).
 *   - Windows: IAT hooking (not yet implemented; the probe fails loudly).
 *
 * Subsystems that REQUIRE interposition (QUIC) call
 * @ref n00b_require_alloc_interposition at first touch; if interposition is
 * not active they get a clear, early error instead of the silent
 * pthread_self trap.
 */

#include "n00b.h"

// ============================================================================
// Interposed implementations (the actual malloc family).
//
// On macOS these are named entry points the __interpose table points at; on
// Linux the strong malloc/free/... symbols forward here.
// ============================================================================

extern void  *n00b_interposed_malloc(size_t size);
extern void   n00b_interposed_free(void *ptr);
extern void  *n00b_interposed_calloc(size_t count, size_t size);
extern void  *n00b_interposed_realloc(void *ptr, size_t size);
extern void  *n00b_interposed_reallocarray(void *ptr, size_t count, size_t size);
extern char  *n00b_interposed_strdup(const char *s);
extern char  *n00b_interposed_strndup(const char *s, size_t n);
extern int    n00b_interposed_posix_memalign(void **memptr, size_t align, size_t size);
extern void  *n00b_interposed_aligned_alloc(size_t align, size_t size);
extern size_t n00b_interposed_malloc_usable_size(void *ptr);

// ============================================================================
// Probe / self-test API.
// ============================================================================

/**
 * @brief Number of times an interposed entry point has run.
 *
 * Monotonic; bumped by every n00b_interposed_* call.  The probe checks that
 * a malloc/free pair advances this — an unambiguous signal that the process
 * actually routed through the shim (vs. linking succeeded but the platform
 * install mechanism was not wired in, e.g. the macOS header was not included
 * in the main executable).
 */
extern uint64_t n00b_alloc_interpose_hits(void);

/**
 * @brief True if libc-malloc interposition is active in this process.
 *
 * Performs a one-shot probe (malloc(1)+free) and checks both that the hit
 * counter advanced and that the returned pointer is owned by the user pool.
 * Cached after the first call.
 */
extern bool n00b_alloc_interposition_active(void);

/**
 * @brief Abort with a clear, platform-specific message if interposition is
 *        not active.
 *
 * @param subsystem Human-readable name of the caller (e.g. "QUIC"), used in
 *                  the error text.
 *
 * Call this at the first-touch entry point of any subsystem that runs
 * vendored libc-malloc code on off-libc worker threads.
 */
extern void n00b_require_alloc_interposition(n00b_string_t *subsystem);
