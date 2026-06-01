/**
 * @file alloc.h
 * @brief Memory allocation interface.
 *
 * Provides the allocator vtable structure, raw allocation/free entry
 * points, allocation info lookup, allocator setup, and convenience
 * macros (n00b_alloc, n00b_alloc_array, n00b_alloc_flex).
 */
#pragma once

#include "n00b.h"
#include "core/alloc_base.h"
#include "core/alloc_mdata.h"
#include "core/mmaps.h"
#include "core/macros.h"
#include "core/align.h"
#include "core/atomic.h"
#include "core/rt_access.h"
#include "core/vargs.h"

struct n00b_allocator_t {
    n00b_calloc_fn            zero_alloc;
    n00b_free_fn              free;
    n00b_allocator_destroy_fn destroy;
    const char               *debug_name;
    uint8_t                   add_inline_header : 1;
    uint8_t                   __system          : 1; // no STW check
    uint8_t                   __md_pool         : 1; // This IS a metadata pool.
    uint8_t                   hidden            : 1; // GC-invisible; see below.
    n00b_allocator_t         *metadata_pool;
    n00b_dict_untyped_t      *metadata;
    void                     *opaque[];
};

typedef uint64_t (*n00b_obj_size_helper)(void *);

/** @brief Magic guard word placed before every managed allocation. */
extern uint64_t n00b_gc_guard;

/**
 * @brief Check whether the GC should scan a mapped region.
 *
 * Returns false for allocator-internal memory that must not be
 * traced during garbage collection.  Hidden allocators' pages are
 * the primary case: they are never registered in the mmap tree
 * (so the GC normally cannot find them), but this function provides
 * a defence-in-depth check for any path that has an mmap record.
 *
 * This is the canonical GC-visibility gate for the allocator
 * abstraction.  Allocator authors only need to set `hidden = true`
 * in their allocator setup; the rest is automatic.
 *
 * @param map Mmap info to check (must not be nullptr).
 * @return    true if the region should be scanned by the GC.
 */
static inline bool
n00b_mmap_is_gc_scannable(n00b_mmap_info_t *map)
{
    if (map->allocator && map->allocator->hidden) {
        /* Hidden pools with out-of-band metadata are still safe to
         * follow into: their metadata dict gives us precise alloc
         * boundaries, so the GC mark can visit those allocs (stamp
         * gc_epoch, trace their outbound pointers) without
         * misinterpreting raw bytes as headers. Hidden pools with
         * no metadata (system_pool, conduit work_pool, etc.) stay
         * opaque because we cannot find an alloc header for them.
         */
        if (map->allocator->metadata_pool != nullptr) {
            return true;
        }
        return false;
    }
    return true;
}

/**
 * @brief Get the current thread's scoped allocator override.
 * @return Current override, or nullptr when this thread uses the runtime default.
 *
 * The returned allocator is only a fallback for APIs whose allocator
 * argument is nullptr.  Explicit `.allocator` kwargs always take
 * precedence over this per-thread override.
 *
 * The override now lives in `n00b_thread_t::current_allocator` reached
 * via `n00b_thread_self()` (D-005), not a `thread_local`.  Before the
 * runtime / calling thread is registered it returns nullptr (the
 * runtime default is used).
 */
extern n00b_allocator_t *n00b_current_allocator(void);

/**
 * @brief Install a current allocator override for this thread.
 * @param allocator Allocator to use for implicit allocations, or nullptr.
 * @return The previous thread-local allocator override.
 *
 * Use this low-level setter only when the previous value is restored on
 * every exit path.  The scoped helpers below are preferred for normal use.
 */
extern n00b_allocator_t *n00b_set_current_allocator(n00b_allocator_t *allocator);

/**
 * @brief Alias for @ref n00b_set_current_allocator.
 * @param allocator Allocator to install for this thread.
 * @return The previous thread-local allocator override.
 */
static inline n00b_allocator_t *
n00b_push_current_allocator(n00b_allocator_t *allocator)
{
    return n00b_set_current_allocator(allocator);
}

/**
 * @brief Restore a prior thread-local allocator override.
 * @param previous Value returned by @ref n00b_set_current_allocator.
 */
extern void n00b_restore_current_allocator(n00b_allocator_t *previous);

/**
 * @brief Guard object for scoped current-allocator overrides.
 *
 * Prefer `n00b_with_allocator(allocator) { ... }` or a local variable
 * annotated with `[[gnu::cleanup(n00b_allocator_scope_exit)]]`.
 */
typedef struct {
    n00b_allocator_t *previous;
    bool              active;
    bool              run;
} n00b_allocator_scope_t;

/**
 * @brief Enter a scoped current-allocator override.
 * @param allocator Allocator to use for implicit allocations in this thread.
 * @return Guard that restores the previous override when exited.
 *
 * @pre @p allocator must outlive every allocation made from it.
 * @post Implicit allocations in this thread use @p allocator until restored.
 */
extern n00b_allocator_scope_t n00b_allocator_scope_enter(n00b_allocator_t *allocator);

/**
 * @brief Exit a scoped current-allocator override.
 * @param scope Guard returned by @ref n00b_allocator_scope_enter.
 *
 * This function is cleanup-safe and idempotent for inactive scopes.
 */
extern void n00b_allocator_scope_exit(n00b_allocator_scope_t *scope);

#define _N00B_WITH_ALLOCATOR(_scope_name, _allocator)                                          \
    for ([[gnu::cleanup(n00b_allocator_scope_exit)]]                                           \
         n00b_allocator_scope_t _scope_name = n00b_allocator_scope_enter((_allocator));         \
         _scope_name.run;                                                                      \
         _scope_name.run = false)

/**
 * @brief Run a block with a thread-local allocator fallback.
 *
 * Example:
 *
 * ```c
 * n00b_with_allocator((n00b_allocator_t *)scratch) {
 *     n00b_string_t *tmp = n00b_cformat("frame [|#|]", frame_name);
 * }
 * ```
 *
 * Only allocations that would otherwise use the runtime default are
 * redirected.  Explicit `.allocator` kwargs still win.  Objects allocated
 * in the scope must not escape unless the scoped allocator outlives them;
 * restore the prior allocator before resetting or destroying scratch
 * arenas/pools.
 */
#define n00b_with_allocator(_allocator)                                                        \
    _N00B_WITH_ALLOCATOR(N00B_CONCAT(_bl_allocator_scope_, __COUNTER__), _allocator)

#define n00b_ensure_allocator(allocator_var)                                                   \
    if (!(allocator_var)) {                                                                    \
        (allocator_var) = n00b_current_allocator();                                            \
        if (!(allocator_var)) {                                                                \
            (allocator_var) = n00b_atomic_load(&n00b_get_runtime()->default_allocator);        \
        }                                                                                      \
        assert(allocator_var);                                                                 \
    }

/*
 * allocator      Allocator to use (nullptr = runtime default).
 * no_scan        If true, GC will not scan this allocation for pointers.
 *                Legacy switch; superseded by scan_kind when scan_kind
 *                != N00B_GC_SCAN_KIND_DEFAULT.
 * mem_debug      Enable memory debugging for this allocation.
 * debug_taint    Taint freed memory with a debug pattern.
 * finalizer      Finalizer callback to run when the object is collected
 *                    or freed. Registered at allocation time, avoiding the
 *                    header lookup that n00b_add_finalizer() requires.
 * finalizer_data Opaque pointer passed to @p finalizer when invoked.
 * scan_kind      Per-allocation GC scan shape (see core/gc_map.h).
 *                DEFAULT (0) falls back to the no_scan switch above.
 * scan_cb        Callback invoked by the GC when scan_kind == CALLBACK.
 *                Requires an allocator with OOB metadata (asserted).
 * scan_user      Opaque pointer passed to scan_cb.
 */

typedef struct {
    n00b_allocator_t   *allocator;
    bool                no_scan;
    bool                mem_debug;
    bool                debug_taint;
    n00b_finalizer_t    finalizer;
    void               *finalizer_data;
    n00b_gc_scan_kind_t scan_kind;
    n00b_gc_scan_cb_t   scan_cb;
    void               *scan_user;
} n00b_alloc_opts_t;

extern const n00b_alloc_opts_t _n00b_default_alloc_opts;

/**
 * @brief Low-level allocation.  Prefer the n00b_alloc() macro family.
 * @param n         Number of elements.
 * @param sz        Size of each element in bytes.
 * @param type_hash typehash(T) for the allocated type (0 = unknown).
 * @param location  Source location string (auto-filled by macro).
 * *
 * @pre Runtime must be initialized (or an explicit allocator must be provided).
 * @post Returned pointer is zero-filled and aligned to `N00B_ALIGN`.
 */
extern void *_n00b_alloc_raw(size_t             n,
                             size_t             sz,
                             uint64_t           type_hash,
                             const char        *location,
                             n00b_alloc_opts_t *opts,
                             +) _kargs : opaque;

/**
 * @brief Free a managed allocation.
 * @param ptr Pointer returned by a prior n00b_alloc call.
 * @pre @p ptr was returned by an n00b_alloc family macro, or is nullptr.
 */
extern void n00b_free(void *ptr);

/**
 * @brief Tear down an allocator, releasing all its resources.
 * @param allocator Allocator to destroy.
 * @pre No outstanding allocations should be in use from @p allocator.
 * @post @p allocator is invalid and must not be used.
 */
extern void n00b_allocator_destroy(n00b_allocator_t *allocator);

/**
 * @brief Look up allocation metadata for an address.
 * @param addr   Address to look up.
 * @param result Output structure to fill.
 *
 * @kw allocator       Allocator to search (nullptr = search all).
 * @kw scan_for_header If true, scan backward for an inline header.
 */
extern void
_n00b_find_alloc_info(void *addr, n00b_alloc_info_t *result) _kargs
{
    n00b_allocator_t *allocator       = nullptr;
    bool              scan_for_header = false;
};

// Get this in the caller's frame.
#define n00b_find_alloc_info(addr, ...)                                                        \
    ({                                                                                         \
        n00b_alloc_info_t _info;                                                               \
        _n00b_find_alloc_info((addr), &_info __VA_OPT__(, __VA_ARGS__));                       \
        _info;                                                                                 \
    })

/**
 * @brief Configure an allocator's vtable and options.
 * @param allocator Allocator to set up.
 * @param alloc     Zero-fill allocation function.
 *
 * @kw free              Free function (nullptr = no-op).
 * @kw destroy           Allocator destroy function (nullptr = no-op).
 * @kw name              Debug name for the allocator.
 * @kw inline_headers    Prepend inline headers to allocations.
 * @kw external_metadata Keep OOB metadata in a separate pool.
 * @kw hidden            Make GC-invisible. Pages allocated through this
 *                       allocator are not registered in the mmap tree,
 *                       so the GC can never discover or scan them.
 *                       Allocator cleanup must use n00b_safe_munmap()
 *                       (which falls back to raw munmap for unregistered
 *                       pages).  See n00b_mmap_is_gc_scannable().
 * @kw __nomap           Skip mmap registration (internal only).
 * @kw __system          Skip STW checks (internal only).
 * @kw __is_md_pool      Mark as a metadata pool (internal only).
 */
extern void
n00b_allocator_setup(n00b_allocator_t *allocator, n00b_calloc_fn alloc) _kargs
{
    n00b_free_fn              free              = nullptr;
    n00b_allocator_destroy_fn destroy           = nullptr;
    char                     *name              = nullptr;
    bool                      inline_headers    = true;
    bool                      external_metadata = true;
    bool                      hidden            = false;
    // DO NOT USE for custom allocators. Skips mmaps.
    bool                      __nomap           = false;
    // DO NOT USE for custom allocators. Skips STW check.
    bool                      __system          = false;
    bool                      __is_md_pool      = false;
};

/**
 * @brief Try to retrieve the inline allocation header for a pointer.
 * @param p Pointer to a managed allocation.
 * @return  Optional inline header (none if @p p is not managed).
 */
static inline n00b_option_t(n00b_inline_hdr_t *) n00b_inline_alloc_header(void *p)
{
    if (!p) {
        return n00b_option_none(n00b_inline_hdr_t *);
    }

    uintptr_t uptr = (uintptr_t)p;

    if (uptr < N00B_ALLOC_HDR_SZ) {
        return n00b_option_none(n00b_inline_hdr_t *);
    }

    if ((uptr & (N00B_ALIGN - 1)) != 0) {
        return n00b_option_none(n00b_inline_hdr_t *);
    }

    n00b_inline_hdr_t *hdr = (n00b_inline_hdr_t *)(uptr - N00B_ALLOC_HDR_SZ);

    if (hdr->guard == n00b_gc_guard) {
        return n00b_option_set(n00b_inline_hdr_t *, hdr);
    }

    return n00b_option_none(n00b_inline_hdr_t *);
}

// Helper: N00B_ALLOC_OPTS(allocator) → &(n00b_alloc_opts_t){.allocator = X}
//         N00B_ALLOC_OPTS()          → nullptr
// Use in macros that optionally accept an allocator pointer.
#define _N00B_ALLOC_OPTS_1(_alloc_ptr) &(n00b_alloc_opts_t){.allocator = (_alloc_ptr)}
#define N00B_ALLOC_OPTS(...) N00B_FIRST(__VA_OPT__(_N00B_ALLOC_OPTS_1(__VA_ARGS__), ) nullptr)

#define n00b_alloc_with_opts(T, opts, ...)                                                     \
    _n00b_alloc_raw(1,                                                                         \
                    sizeof(T),                                                                 \
                    typehash(T *),                                                             \
                    N00B_LOC_STRING(),                                                         \
                    opts __VA_OPT__(, __VA_ARGS__))

#define n00b_alloc_array_with_opts(T, N, opts, ...)                                            \
    _n00b_alloc_raw((N),                                                                       \
                    sizeof(T),                                                                 \
                    typehash(T *),                                                             \
                    N00B_LOC_STRING(),                                                         \
                    opts __VA_OPT__(, __VA_ARGS__))

/* Flex allocations are not exact T1 objects: the tail can carry additional
 * words with a different shape. Keep them out of the typehash->layout upgrade
 * until there is a descriptor that models the flexible tail. */
#define n00b_alloc_flex_with_opts(T1, T2, N2, opts, ...)                                       \
    _n00b_alloc_raw(1,                                                                         \
                    (sizeof(T1) + sizeof(T2) * (N2)),                                          \
                    0,                                                                         \
                    N00B_LOC_STRING(),                                                         \
                    opts __VA_OPT__(, __VA_ARGS__))

#define _n00b_kargs_name(base_name) N00B_CONCAT(N00B_CONCAT(n00b_, base_name), _init)
#define n00b_kargs(base_name, ...)                                                             \
    kw_func(_n00b_kargs_name(base_name) __VA_OPT__(, __VA_ARGS__))

// This should only be used in implementation headers for generic
// container types. If you're using it for anything else, you're doing
// it wrong.
#define n00b_alloc_size_with_opts(n, sz, opts, ...)                                            \
    _n00b_alloc_raw(n, sz, 0, N00B_LOC_STRING(), opts __VA_OPT__(, __VA_ARGS__))

#define n00b_alloc(T, ...) n00b_alloc_with_opts(T, nullptr __VA_OPT__(, __VA_ARGS__))

#define n00b_new_kargs(T, base_name, ...)                                                      \
    n00b_alloc(T, n00b_kargs(base_name __VA_OPT__(, __VA_ARGS__)))

#define n00b_new_vargs(T, __vargs)                                                             \
    n00b_alloc(T, n00b_vargs __vargs)

// Caller should put vargs in parentheses, to clearly delineate, and will make the expansion a
// function-like macro.
#define n00b_new_both(T, base_name, __vargs, ...)                                              \
    n00b_alloc(T, n00b_vargs __vargs, n00b_kargs(base_name __VA_OPT__(, __VA_ARGS__)))

#define n00b_alloc_array(T, N, ...)                                                            \
    n00b_alloc_array_with_opts(T, N, nullptr __VA_OPT__(, __VA_ARGS__))

#define n00b_alloc_flex(T1, T2, N2, ...)                                                       \
    n00b_alloc_flex_with_opts(T1, T2, N2, nullptr __VA_OPT__(, __VA_ARGS__))

// This should only be used in implementation headers for generic
// container types. If you're using it for anything else, you're doing
// it wrong.
#define n00b_alloc_size(n, sz, ...)                                                            \
    n00b_alloc_size_with_opts(n, sz, nullptr __VA_OPT__(, __VA_ARGS__))

/**
 * @brief Get the inline header for a managed object.
 * @param p Pointer to a managed object.
 * @return  Optional inline header.
 */
extern n00b_option_t(n00b_inline_hdr_t *) n00b_object_header(void *p);
