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
 * Backing allocator: @c rt->user_pool (hidden, non-moving, OOB metadata).
 * Plain malloc/calloc return the exact pool allocation base so n00b callers
 * can still release picotls-returned buffers with @ref n00b_free. Explicit
 * over-aligned APIs may return an interior aligned pointer; free/realloc use
 * n00b's OOB metadata to recover the base while the runtime is live. The shim
 * also records backing user-pool page ranges in static process state so late
 * process-exit frees after @c n00b_shutdown can identify n00b-owned pointers
 * without dereferencing runtime state.
 *
 * Lifecycle: interposition is live from process start, but the user pool
 * only exists after n00b_init.  Before the runtime is ready the shim
 * delegates to the real libc symbols (resolved via dlsym(RTLD_NEXT)); those
 * pre-init allocations run on the main thread with a full TCB, so libc is
 * safe there.  While the runtime is live, free()/realloc() resolve ownership
 * by address so a pointer handed out before init is freed back through libc,
 * and a pool pointer is freed back through the pool. After shutdown, pointers
 * in remembered user-pool ranges are ignored instead of being handed to libc;
 * the process is exiting and the runtime may have lived on main()'s stack.
 *
 * Install mechanism is platform-specific:
 *   - macOS:   QUIC/picotls translation units are redirected at compile time
 *              by `core/alloc_interpose_shim.h`. dyld `__DATA,__interpose`
 *              tables are useful only across image boundaries; they do not
 *              interpose the image that contains the table, so the static
 *              libn00b/main-executable path cannot rely on them.
 *   - Linux:   strong `malloc`/`free`/... symbols defined in libn00b
 *              override libc's process-wide. QUIC/picotls are also compiled
 *              with the same shim for uniform source-level coverage.
 *   - Windows: IAT hooking is not yet implemented; QUIC/picotls still use the
 *              compile-time shim where they are built with n00b.
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
// The compile-time shim maps vendored malloc-family calls here. On Linux the
// strong malloc/free/... symbols also forward here for process-wide coverage.
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
#if defined(__linux__)
/* GNU allocation-family entry points covered by Linux process-wide
 * interposition. */
extern void  *n00b_interposed_memalign(size_t align, size_t size);
extern void  *n00b_interposed_valloc(size_t size);
extern void  *n00b_interposed_pvalloc(size_t size);
#endif

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
 * @brief Mark the default runtime as safe for allocator-interpose lookups.
 *
 * Internal lifecycle hook called by @ref n00b_init after startup completes.
 * It keeps process-wide Linux allocation interposition from dereferencing a
 * stale stack runtime during process teardown if an application exits without
 * calling @ref n00b_shutdown.
 */
extern void n00b_alloc_interpose_runtime_start(void);

/**
 * @brief Resolve the real libc allocator symbols NOW, on the calling (main)
 * thread, before any worker is spawned.
 *
 * ensure_reals() uses dlsym(RTLD_NEXT, ...), which reaches into dyld; on a raw
 * Mach worker thread (no pthread/dyld TSD) that traps (SIGTRAP). If the first
 * interposed libc call happens on a worker before the reals are resolved, the
 * process crashes. n00b_init must call this BEFORE it starts the conduit IO
 * service worker (and any other thread), so dlsym only ever runs on the main
 * thread. Idempotent and cheap once resolved.
 */
extern void n00b_alloc_interpose_resolve_reals(void);

/**
 * @brief Mark the default runtime as unavailable to allocator interposition.
 *
 * Internal lifecycle hook called by @ref n00b_shutdown immediately before the
 * default runtime handle is cleared.
 */
extern void n00b_alloc_interpose_runtime_stop(void);

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
