/**
 * @file runtime.h
 * @brief Runtime state and initialization.
 *
 * Defines the n00b_runtime_t structure that holds global state (threads,
 * memory maps, allocators) and the n00b_init() entry point.
 */
#pragma once

#if !defined(N00B_THREADS_MAX)
#define N00B_THREADS_MAX 4096
#endif

#include <assert.h>

#include "n00b.h"
#include "core/alloc_base.h"
#include "core/rt_access.h"
#include "core/thread.h"
#include "adt/array.h"
#include "adt/list.h"
#include "adt/option.h"
#include "adt/variant.h"
#include "adt/interval_tree.h"
#include "core/pool.h"
#include "conduit/conduit_types.h"

typedef struct n00b_runtime_t n00b_runtime_t;

// Forward declarations to avoid circular includes.
typedef struct n00b_conduit_service        n00b_conduit_service_t;
typedef struct n00b_http_connection_pool   n00b_http_connection_pool_t;
typedef struct n00b_acme_tls_state         n00b_acme_tls_state_t;
typedef struct n00b_static_identity_entry_t n00b_static_identity_entry_t;

/**
 * @brief Variant type for mmap registry interval trees.
 *
 * Mmap records and lightweight sub-range records are stored in separate
 * trees, but share the same concrete node/data shape so back-pointers and
 * registry helpers can stay uniform.
 */
typedef n00b_variant_t(n00b_mmap_info_t *, n00b_alloc_range_t *) n00b_mmap_data_t;

struct n00b_mmap_ctx_t {
    n00b_interval_tree_t(n00b_mmap_data_t) *mmap_tree;
    n00b_interval_tree_t(n00b_mmap_data_t) *range_tree;
    n00b_static_identity_entry_t *static_identities;
    _Atomic int64_t  tid_lock;
    n00b_pool_t      pool;
};

struct n00b_runtime_t {
    n00b_array_t(char *) argv;
    n00b_array_t(char *) envp;
    n00b_mmap_ctx_t             mmaps;
    _Atomic uint32_t            next_thread_slot;
    _Atomic uint32_t            live_threads;
    _Atomic bool                startup_complete;
    /* Set by `n00b_shutdown` before tearing anything down.  Spin-wait
     * helpers (`n00b_futex_wait_for_value`, `n00b_futex_wait_on_mask`)
     * check this and break out instead of looping forever when the
     * thread they were waiting on is being reaped during shutdown. */
    _Atomic bool                shutdown_started;
    _Atomic(n00b_allocator_t *) default_allocator;
    n00b_arena_t               *default_arena; // GC'd arena (when using default allocator)
    n00b_pool_t                 system_pool;   // System pool for root list & lock records.
    /* GC-VISIBLE, non-moving pool for GC-reclaimable runtime structs —
     * currently the per-thread `n00b_thread_t` (WP-3a / D-034).  NOTE: named
     * `runtime_obj_pool` to avoid colliding with the upstream `user_pool`
     * below, which is a HIDDEN leak-tracking pool for application allocations
     * (the WP-close deconfliction — D-034/D-039; the two are NOT the same pool:
     * this one is GC-visible, that one is hidden).  Unlike `system_pool`
     * (hidden + bulk-freed at teardown) and `conduit_pool` (also hidden),
     * `runtime_obj_pool` is initialized with `hidden = false` and WITHOUT
     * `.__system`, so the GC sees its allocations as ordinary objects: they
     * live as long as reachable and are reclaimed once unreferenced.  Being a
     * pool, it is NON-MOVING — the GC never relocates an allocation made from
     * it, which keeps the raw `rt->threads[].thread` pointers,
     * `n00b_thread_self()`'s masked recovery, and the explicit thread-struct /
     * record / lock-chain scan in gc.c all valid. */
    n00b_pool_t                 runtime_obj_pool;
    n00b_list_t(n00b_gc_root_t) gc_roots;      // User-registered GC roots.
    /* Non-hidden, non-arena allocators (e.g. caller-owned pools created
     * with `hidden = false`).  The GC walks every page of each pool in
     * this list during a collect so pointers FROM pool memory INTO the
     * default arena get traced/forwarded.  Hidden pools are NOT in
     * this list.  Backed by system_pool. */
    n00b_list_t(n00b_allocator_t *) scannable_pools;
    /* Legacy fallback registry kept for callers that attach a
     * finalizer to an allocation from a pool without per-alloc
     * metadata. The OOB-backed fast path (the finalizer slot on
     * n00b_oob_hdr_t) is the preferred one — callers that need
     * finalizers MUST allocate from a metadata-bearing pool.
     * This list grows under the legacy path and is O(N) walked
     * on n00b_free, so it must stay small. */
    n00b_list_t(n00b_finalizer_info_t *) finalizers;
    /* Every pool created with @c external_metadata=true registers
     * itself here so the GC mark phase can iterate its metadata dict
     * directly. Each metadata-bearing alloc with @c alive set is a
     * root for the mark pass; entries reached during mark get
     * stamped with @c gc_current_epoch on their OOB header. Entries
     * still @c alive after mark whose epoch is stale are leaks —
     * the sweep returns them to the pool.  System_pool and the
     * hidden no-metadata pools sit outside this list and continue
     * to use the global rt->finalizers fallback. */
    n00b_list_t(n00b_allocator_t *) metadata_pools;
    /* Monotonic counter incremented at the start of every GC. Used
     * by the metadata-pool sweep above to detect leaks (stale
     * epoch = handed-out but never reached). */
    _Atomic(uint64_t)           gc_current_epoch;
    /* When set, the next collection prints file_name + tinfo +
     * alloc_len for each metadata-pool leak it finds before
     * returning the slot to its pool. Toggled by
     * n00b_debug_find_leaks. */
    _Atomic(bool)               debug_leak_detect;
    n00b_dict_untyped_t        *type_registry;     // typehash -> n00b_type_info_t *
    n00b_pool_t                 conduit_pool;      // Pool for conduit infra (registered as GC root).
    /* User-space pool for application allocations that want
     * leak-tracking. Initialised with external_metadata=true so
     * every alloc carries an OOB record (alive bit + gc_epoch +
     * file_name + tinfo) and participates in
     * n00b_debug_find_leaks. NOT for hot-path traffic — the
     * per-alloc dict+OOB bookkeeping makes this pool more
     * expensive than system_pool or conduit_pool. Use it for
     * client allocations whose lifecycle the application owns
     * and that need to be auditable for leaks. */
    n00b_pool_t                 user_pool;
    n00b_dict_untyped_t        *sub_map;           // conduit subscription handle -> sub ptr
    n00b_conduit_t             *default_conduit;   // Default conduit for IO service.
    n00b_conduit_service_t     *default_service;   // Service thread pool (IO + signal).
    n00b_conduit_fd_owner_t    *stdin_owner;       // Managed fd 0.
    n00b_conduit_fd_owner_t    *stdout_owner;      // Managed fd 1.
    n00b_conduit_fd_owner_t    *stderr_owner;      // Managed fd 2.
    n00b_conduit_topic_base_t  *stdout_topic;      // Typed stdout buffer topic.
    n00b_conduit_topic_base_t  *stderr_topic;      // Typed stderr buffer topic.
    /* Thread slot table.  Sized at init time per the @c max_threads
     * kwarg (defaults to @c N00B_THREADS_MAX).  Allocated from
     * @c system_pool so that other threads can read it safely
     * (non-moving, hidden from GC).  @c max_threads is the number of
     * slots and the modulo used for slot acquisition. */
    uint32_t                    max_threads;
    n00b_thread_record_t       *threads;
    /* Callstack reclamation bookkeeping (WP-3a Phase 2, D-034).  Both
     * lists are zero-initialized by the runtime's zero-fill at init (a
     * null head + a 0 lock is the correct empty state), so no explicit
     * init call is needed.
     *
     * `callstack_pool` is the free-list a spawn draws an 8 MiB callstack
     * region from before falling back to a fresh `n00b_mmap`; a worker's
     * region returns here at OS-confirmed death instead of being unmapped
     * (glibc stack-cache / Go stack-pool precedent).  The list links
     * through `n00b_callstack_t::pool_next`; `callstack_pool_lock` guards
     * it and `callstack_pool_count` tracks the pooled-region count for the
     * keep-N trim cap (see `N00B_CALLSTACK_POOL_MAX` / DF-4).
     *
     * `reap_pending` is the queue of workers that have published exit but
     * await OS-death confirmation (macOS dead Mach port / Linux
     * CLONE_CHILD_CLEARTID futex).  A worker enqueues its own struct at the
     * launcher exit (before self-terminate); the reaper drains it from the
     * callstack-pool slow path and the conduit signal thread, reclaiming
     * only the workers whose death edge has fired.  The queue links through
     * `n00b_thread_t::reap_next`; `reap_lock` guards it.  This is NOT the
     * GC-owned struct lifetime (D-034): the struct stays in `runtime_obj_pool`;
     * only the callstack/TCB/slot are reclaimed here. */
    struct n00b_callstack_t    *callstack_pool;
    _Atomic uint32_t            callstack_pool_lock;
    uint32_t                    callstack_pool_count;
    struct n00b_thread_t       *reap_pending;
    _Atomic uint32_t            reap_lock;
    n00b_base_allocator_t       slab_allocator;
    n00b_futex_t                stw;
    n00b_futex_t                stw_generation;
    uint32_t                    stw_nesting;
    const char                 *theme_name;    // Active theme name (set during init).
    n00b_unicode_ctx_t         *unicode_ctx;   // Phase 4.5 unicode subsystem state.
    n00b_regex_ctx_t           *regex_ctx;     // Regex port-side caches.
    /* Per-runtime HTTP connection pool — populated lazily on first
     * `n00b_http_request_sync` / `n00b_http_request` call via
     * `n00b_http_get_connection_pool(runtime)`.  Drained at runtime
     * shutdown.  See include/internal/net/http/http_pool.h for the
     * pool API. */
    _Atomic(n00b_http_connection_pool_t *) http_connection_pool;
    /* Per-runtime picotls base context + chain verifier for the h1
     * TLS transport (see src/net/quic/acme_tls.c).  Lazy-initialized
     * on first connect; the slot holds an opaque pointer because the
     * underlying picotls types aren't part of n00b's public surface. */
    _Atomic(n00b_acme_tls_state_t *)       acme_tls_state;
};

/**
 * @brief Initialize the n00b runtime.
 * @param rt   Runtime structure to initialize.
 * @param argc Argument count from main().
 * @param argv Argument vector from main().
 *
 * @kw allocator    Allocator to use (nullptr = GC'd arena).
 * @kw envp         Environment pointer (nullptr = inherit).
 * @kw numeric_locale Numeric locale string ("" = default).
 * @kw fd_limit     File descriptor limit (0 = don't change, <0 = don't set).
 * @kw max_threads  Maximum thread count (default N00B_THREADS_MAX).
 *
 * @pre Must be called exactly once, from the main thread, before any
 *      other n00b API.
 * @post `n00b_get_runtime()` returns a valid pointer. The calling
 *       thread is registered with the STW subsystem.
 */
extern void
n00b_init(n00b_runtime_t *rt, int argc, char *argv[]) _kargs
{
    n00b_allocator_t *allocator       = nullptr; // nullptr = use a GC'd arena
    char             **envp           = nullptr;
    char              *numeric_locale = "";
    int                fd_limit       = 0; // Less than 0 = "don't set"
    unsigned int       max_threads    = N00B_THREADS_MAX;
};

/**
 * @brief Plain-C wrapper for n00b_init() with default kargs.
 *
 * Callable from code not compiled through ncc (e.g. startup shims
 * for AOT-compiled binaries).  Heap-allocates an n00b_runtime_t
 * internally.
 */
extern void n00b_init_simple(int argc, char *argv[]);

/**
 * @brief Shut down the runtime, stopping all service threads.
 * @pre  Must be called from the main thread before returning from main().
 * @post All conduit IO threads have exited.
 */
extern void n00b_shutdown(void);

/**
 * @brief Shut down the runtime and terminate the process.
 * @param code Process exit status.
 *
 * Prefer this over calling `exit()` directly from n00b-aware programs,
 * so conduit IO and other runtime services get a chance to drain.
 */
extern void n00b_exit(int code);

/**
 * @brief Get the runtime's default allocator.
 * @return Pointer to the default allocator.
 */
static inline n00b_allocator_t *
n00b_default_allocator(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();

    assert(rt);
    assert(rt->default_allocator);

    return rt->default_allocator;
}

/**
 * @brief Get the runtime's slab (pool) allocator.
 * @return Pointer to the slab allocator.
 */
static inline n00b_allocator_t *
n00b_slab_allocator(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();

    assert(rt);
    return (n00b_allocator_t *)&rt->slab_allocator;
}

/**
 * @brief Get the runtime's system pool allocator.
 *
 * The system pool is non-arena, non-GC-scanned, never moved, and never
 * freed. Use it for objects whose addresses must stay valid outside the
 * GC's view — e.g. environment slots (`core/env.c`) or heap literals
 * baked into JIT-generated code as raw immediates (`slay/codegen.c`).
 *
 * @return Pointer to the system pool allocator.
 */
static inline n00b_allocator_t *
n00b_system_allocator(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();

    assert(rt);
    return (n00b_allocator_t *)&rt->system_pool;
}
