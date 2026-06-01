/**
 * @file callstack.h
 * @brief OS-native call-stack allocation + TLS-free identity geometry.
 *
 * Provides the n00b OS-stack-allocation capability that the WP-001
 * thread foundation builds on:
 *
 *   - `n00b_callstack_alloc` / `n00b_callstack_free` lay an OS-mapped
 *     stack region (backed by `n00b_mmap`/`n00b_munmap`) out with a
 *     fixed-offset identity ID word and a non-accessible guard page,
 *     and register the usable region with the global mmap interval
 *     tree as `n00b_mmap_stack` (the same kind the main-thread stack
 *     registration uses) so the GC stack scan can find it.
 *
 *   - `n00b_callstack_id_word` is the single canonical SP->region
 *     recovery helper for worker callstacks.  Per D-014 it is O(1) and
 *     lock-free: every n00b worker callstack is carved to a fixed
 *     power-of-2 size `N00B_CALLSTACK_REGION_SIZE` and aligned on that
 *     same boundary, so the region base is recovered from any in-region
 *     SP by masking — `base = SP & ~(S-1)` — with NO mmap interval-tree
 *     lookup and NO lock.  The ID word lives at a fixed offset from the
 *     base.
 *
 * The main thread's kernel-provided stack is NOT in scope for this
 * helper: its base is not a power-of-2 boundary, so masking cannot
 * recover it.  D-014 places the main-thread O(1) recovery in Phase 2
 * as a range check against the bounds stored in its
 * `n00b_thread_record_t`, living in `n00b_thread_self()` — not here.
 *
 * Phase 1 delivers the geometry + the worker recovery helper only.
 * Wiring `n00b_thread_self()` / identity to this surface is Phase 2;
 * thread creation is Phase 3.
 *
 * ## ID-word write protocol (geometry contract for Phases 2/3)
 * The identity ID word lives at the highest usable word of the carved
 * `S`-aligned region (`base + N00B_CALLSTACK_REGION_SIZE - 8`).  The
 * stack grows downward (high address -> low address) on every target
 * ABI, so the ID word sits at the base of the stack, farthest from the
 * guard page; a thread writes its own ID word exactly once, at entry,
 * before the first `n00b_thread_self()` call (workers, Phase 3).
 */
#pragma once

#include "n00b.h"
#include "core/mmaps.h"
#include "adt/option.h"

/**
 * @brief Power-of-2 usable region size `S` for every n00b worker callstack (DF #2).
 *
 * Resolved at Phase-1 implementation time (D-014).  Because
 * `n00b_mmap` returns only a page-aligned region — it offers no
 * power-of-2 *alignment* knob — `n00b_callstack_alloc` over-allocates
 * `2*S` and carves an `S`-aligned, `S`-sized usable sub-region out of
 * it.  With every worker region the same size `S` and aligned on `S`,
 * the recovery helper recovers the region base from any SP with a
 * single mask `base = SP & ~(S-1)` — O(1), lock-free, no interval-tree
 * lookup (D-004).
 *
 * `S` MUST be a power of two and a multiple of the page size; 8 MiB
 * (2^23) satisfies both on every target page size (<= 64 KiB).
 */
#define N00B_CALLSTACK_REGION_SIZE ((uint64_t)(8 * 1024 * 1024))

/**
 * @brief Compile-time mask used by the O(1) SP->base recovery (`~(S-1)`).
 */
#define N00B_CALLSTACK_REGION_MASK (~(N00B_CALLSTACK_REGION_SIZE - 1))

/**
 * @brief Width of the identity ID word.
 *
 * The ID word is one 64-bit word at the *highest* word-aligned address
 * of the carved region: `id_word_addr = base + S - 8`.  Placing it at
 * the base (top of a downward-growing stack) keeps it farthest from the
 * low-end guard page, so a stack overflow trips the guard before it can
 * corrupt identity.  Its offset from the region base is the fixed
 * constant `N00B_CALLSTACK_REGION_SIZE - N00B_CALLSTACK_ID_WORD_SIZE`.
 */
#define N00B_CALLSTACK_ID_WORD_SIZE ((uint64_t)sizeof(uint64_t))

/**
 * @brief Guard-page size policy (DF #3).
 *
 * The guard region is a non-accessible (`PROT_NONE` /
 * `n00b_mmap_perms_no_access`) band of `N00B_CALLSTACK_GUARD_PAGES`
 * pages at the LOW end of the carved region — the direction a
 * downward-growing stack overflows into.  One page is sufficient to
 * fault on the first overflowing access on all three target OSes
 * (Linux/macOS/Windows all fault on any access to a `PROT_NONE` page);
 * the overflow *handler* itself is WP-003, this is only the page.  The
 * size is expressed in pages (not bytes) so it tracks each OS's actual
 * page size via `n00b_page_size`.
 */
#define N00B_CALLSTACK_GUARD_PAGES ((uint64_t)1)

// ============================================================================
// Error codes
//
// `n00b_callstack_alloc` returns `n00b_result_t` whose Err channel carries
// two disjoint kinds of code:
//
//   - A *real* POSIX `errno` (positive), surfaced verbatim from the
//     underlying `n00b_mmap` / `mprotect` primitives via
//     `n00b_check_posix` / `n00b_check_mmap`.
//   - A *library-domain* code for failures that did not originate from a
//     libc syscall (an over-large request, a failed mmap-tree
//     registration, a Win32 `VirtualProtect` failure). Per the API
//     guidelines (§5.1) these are negative integers so they cannot
//     collide with any positive `errno`.
//
// `n00b_callstack_err_str` (§5.5) interprets both: a recognized domain
// code returns its own description, anything else is folded through
// `n00b_errno_str` so a caller can stringify the Err channel without
// first having to know which kind of code it holds.
// ============================================================================

/** @brief Requested usable size exceeds the fixed region's usable span. */
#define N00B_ERR_CALLSTACK_SIZE_TOO_LARGE (-1)

/** @brief An mmap-interval-tree registration (stack region or guard band) failed. */
#define N00B_ERR_CALLSTACK_REGISTER_FAILED (-2)

/** @brief Marking the guard band non-accessible failed (Win32 VirtualProtect). */
#define N00B_ERR_CALLSTACK_PROTECT_FAILED (-3)

/**
 * @brief A caller-supplied `custom_stack` region is too small or cannot be
 *        made `S`-aligned.
 *
 * `n00b_callstack_alloc_over` carves an `S`-aligned, `S`-sized usable region
 * out of caller memory.  Because `n00b_mmap` offers no power-of-2 alignment
 * knob the same way (see DF #2), the caller region must be at least
 * `2 * N00B_CALLSTACK_REGION_SIZE` bytes so an `S`-aligned sub-region can
 * always be carved from anywhere inside it; a region whose span between its
 * `S`-aligned ceiling and its end is less than `S` is rejected with this
 * code.  See `n00b_callstack_alloc_over`'s size/alignment contract.
 */
#define N00B_ERR_CALLSTACK_REGION_UNUSABLE (-4)

/**
 * @brief Location + size of an OS-allocated call stack.
 *
 * Mirrors thread.md's "stack info" type.  The whole `2*S` over-mapping
 * is trimmed down (head + tail pages unmapped) to exactly the carved
 * `S`-aligned region, so `region_start == base` and
 * `region_size == N00B_CALLSTACK_REGION_SIZE`.  The usable sub-region
 * (above the low-end guard band) is what the mmap interval tree carries
 * as `n00b_mmap_stack` for the GC scan.
 */
typedef struct n00b_callstack_t {
    void             *region_start; ///< Carved region base (S-aligned; == guard_start).
    uint64_t          region_size;  ///< Total carved bytes (== N00B_CALLSTACK_REGION_SIZE).
    void             *guard_start;  ///< Guard band start (== region_start).
    uint64_t          guard_size;   ///< Guard band bytes (PROT_NONE).
    void             *stack_low;    ///< Lowest usable address (guard band end).
    void             *stack_high;   ///< One past the highest usable address (== base + S).
    n00b_mmap_info_t *stack_map;    ///< Usable-region mmap record (n00b_mmap_stack).
    n00b_mmap_info_t *guard_map;    ///< Guard-band mmap record (perms_no_access).
    /**
     * @brief True when the backing pages are caller-owned (`custom_stack`).
     *
     * Set by `n00b_callstack_alloc_over`, clear for `n00b_callstack_alloc`.
     * `n00b_callstack_free` keys off this: a caller-owned region's mmap
     * interval-tree registrations are still dropped (so the GC tree stays
     * balanced), but the backing pages are NEVER unmapped — ownership stays
     * with the caller (D-025).
     */
    bool              caller_owned;
    /**
     * @brief Free-list link for the runtime callstack pool (WP-3a Phase 2, D-034).
     *
     * When a worker's region is returned to the pool at OS-confirmed death
     * (`n00b_callstack_pool_return`) instead of being unmapped, the region
     * is threaded onto `n00b_runtime_t::callstack_pool` through this field.
     * Unused (and meaningless) while a region is live or has been handed to
     * a worker.  Never set for `caller_owned` regions — those are never
     * pooled (the backing pages belong to the caller).
     */
    struct n00b_callstack_t *pool_next;
} n00b_callstack_t;

/**
 * @brief Keep-N cap for the runtime callstack pool (WP-3a Phase 2, DF-4).
 *
 * The pool retains up to this many reclaimed 8 MiB regions for reuse; a
 * return beyond the cap unmaps the region instead (so a burst of
 * short-lived workers does not pin an unbounded amount of address space).
 * A simple keep-N policy is the WP-3a choice; a tuned/adaptive trim policy
 * is a later refinement (DF-4).  At 8 MiB/region the default cap bounds the
 * pool's resident address space at `N00B_CALLSTACK_POOL_MAX * 8 MiB`.
 */
#define N00B_CALLSTACK_POOL_MAX ((uint32_t)64)

/**
 * @brief Allocate an OS-native worker call stack with identity + guard geometry.
 *
 * Over-allocates `2 * N00B_CALLSTACK_REGION_SIZE` via `n00b_mmap`,
 * carves an `S`-aligned, `S`-sized usable region out of it, unmaps the
 * surrounding (head + tail) pages, carves a low-end guard band
 * (`PROT_NONE`), and registers the usable sub-region with the global
 * mmap interval tree as `n00b_mmap_stack` so the GC stack scan finds it.
 * The guard band is registered as its own `n00b_mmap_stack` record with
 * `n00b_mmap_perms_no_access` so its inaccessibility is observable
 * without faulting.
 *
 * Because the carved region is `S`-aligned and `S`-sized, any SP within
 * it recovers the region base by masking (`n00b_callstack_id_word`),
 * with no lookup and no lock.
 *
 * Does NOT write the ID word — that is the thread's responsibility at
 * entry (Phase 3), per the write protocol documented above.
 *
 * @param requested_size Desired usable stack bytes; 0 selects the full
 *                        usable span.  Must fit within `S` minus the
 *                        guard band and ID word; a larger request is an
 *                        error (the whole region is fixed at `S` so
 *                        masking stays valid).
 *
 * @kw allocator Allocator that owns the `n00b_callstack_t` bookkeeping
 *               struct and is recorded on the mmap registrations
 *               (defaults to the runtime allocator).
 *
 * @return The allocated call stack on success, or an error code on
 *         failure: a real `errno` from the underlying mmap/mprotect, or
 *         one of the negative library-domain codes
 *         (`N00B_ERR_CALLSTACK_SIZE_TOO_LARGE` for an over-large
 *         request, `N00B_ERR_CALLSTACK_REGISTER_FAILED` for a failed
 *         mmap-tree registration, `N00B_ERR_CALLSTACK_PROTECT_FAILED`
 *         for a failed guard-band protect). Stringify either kind via
 *         `n00b_callstack_err_str`.
 *
 * @pre  Runtime is initialized (`n00b_page_size` is set).
 * @post On success the usable region is registered as `n00b_mmap_stack`
 *       and the guard band is mapped non-accessible.
 */
extern n00b_result_t(n00b_callstack_t *)
n00b_callstack_alloc(uint64_t requested_size) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Free an OS-native call stack allocated by `n00b_callstack_alloc`.
 *
 * Deregisters both the usable-region and guard-band mmap records and
 * unmaps the carved region.
 *
 * @param stack Call stack to free (from `n00b_callstack_alloc`).
 *
 * @pre  No live thread is currently running on @p stack.
 * @post The region is unmapped and its mmap registrations are gone.
 */
extern void n00b_callstack_free(n00b_callstack_t *stack);

/**
 * @brief Get a worker callstack from the runtime pool, or allocate a fresh one.
 *
 * The pool entry point for `n00b_thread_spawn` (WP-3a Phase 2, D-034).  If the
 * runtime callstack pool holds a previously-reclaimed region, this pops and
 * returns it (its mmap-tree registrations and guard band are still live from
 * its first allocation — the geometry contract has each new worker rewrite the
 * ID word at entry, so a reused region needs no re-registration).  Otherwise it
 * falls back to a fresh `n00b_callstack_alloc(0)`.
 *
 * Reclaimed regions return to the pool ONLY at OS-confirmed worker death
 * (`n00b_callstack_pool_return`, driven by the reaper), never at the join
 * handshake — so a region handed out here is guaranteed to be off any worker's
 * live stack.
 *
 * @kw allocator Allocator that owns the `n00b_callstack_t` bookkeeping struct
 *               for the fresh-allocation fallback (defaults to the runtime
 *               allocator).  Ignored on a pool hit (the pooled struct is
 *               reused as-is).
 *
 * @return The callstack on success, or the same error channel
 *         `n00b_callstack_alloc` produces on the fresh-allocation path.
 *         Stringify via `n00b_callstack_err_str`.
 *
 * @pre  Runtime is initialized.
 * @post On success the returned region is registered as `n00b_mmap_stack` and
 *       is NOT on the pool free-list.
 */
extern n00b_result_t(n00b_callstack_t *)
n00b_callstack_pool_get() _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Return a dead worker's callstack to the runtime pool (or unmap it).
 *
 * Called by the reaper at OS-confirmed worker death (WP-3a Phase 2, D-034):
 * the region is known to be off the worker's live stack, so it is safe to
 * recycle.  Up to `N00B_CALLSTACK_POOL_MAX` regions are retained on the pool
 * free-list (with their mmap-tree registrations LEFT LIVE for reuse); a return
 * beyond the cap unmaps the region via `n00b_callstack_free` (DF-4 keep-N).
 *
 * A `caller_owned` (`custom_stack`) region is NEVER pooled — its backing pages
 * belong to the caller; this routine routes it straight to `n00b_callstack_free`
 * (which drops the registrations WITHOUT unmapping the caller's memory).  A
 * nullptr @p stack is a no-op.
 *
 * @param stack The callstack to reclaim (from a confirmed-dead worker).
 *
 * @pre  No thread is running on @p stack (the OS has confirmed the worker is
 *       off it — dead Mach port / CLONE_CHILD_CLEARTID futex).
 * @post @p stack is either on the pool free-list (registrations live, ready for
 *       a later `n00b_callstack_pool_get`) or fully unmapped.
 */
extern void n00b_callstack_pool_return(n00b_callstack_t *stack);

/**
 * @brief A caller-supplied backing region for a `custom_stack` worker.
 *
 * Describes a contiguous block of memory the caller already owns (however
 * it was obtained) that `n00b_callstack_alloc_over` lays the n00b callstack
 * geometry over — so a worker spawned with `n00b_thread_spawn(.custom_stack
 * = …)` resolves `n00b_thread_self()` in O(1) (D-025).  The caller retains ownership:
 * the region is never unmapped or freed by n00b (see
 * `n00b_callstack_alloc_over` / `n00b_callstack_free`).
 */
typedef struct n00b_callstack_region_t {
    void    *base; ///< Lowest address of the caller-owned backing region.
    uint64_t size; ///< Region length in bytes.
} n00b_callstack_region_t;

/**
 * @brief Lay the n00b callstack geometry over a CALLER-OWNED memory region.
 *
 * The `custom_stack` path (D-025).  Imposes exactly the same `S`-aligned
 * power-of-2 + low-end guard band + ID-word geometry that
 * `n00b_callstack_alloc` produces — `N00B_CALLSTACK_REGION_SIZE` /
 * `N00B_CALLSTACK_REGION_MASK` / `N00B_CALLSTACK_ID_WORD_SIZE` — but over a
 * region the caller already owns instead of a fresh `n00b_mmap`.  An
 * `S`-aligned, `S`-sized usable sub-region is carved from @p region and
 * registered with the global mmap interval tree as `n00b_mmap_stack` so the
 * GC stack scan finds it; the carved region's `caller_owned` flag is set so
 * `n00b_callstack_free` drops the registrations WITHOUT unmapping the
 * caller's pages.
 *
 * ## Size / alignment contract (DF #2)
 * The mask `base = SP & ~(S-1)` must recover the region base from any SP in
 * it, so the usable region must be `S`-aligned and `S`-sized.  Because the
 * caller's @p base need not be `S`-aligned, the region must be large enough
 * that an `S`-aligned, `S`-sized sub-region fits inside it: @p size MUST be
 * at least `2 * N00B_CALLSTACK_REGION_SIZE` (the same over-allocate factor
 * `n00b_callstack_alloc` uses).  A region whose `S`-aligned ceiling leaves
 * fewer than `S` usable bytes before its end is rejected with
 * `N00B_ERR_CALLSTACK_REGION_UNUSABLE`.  The caller-supplied bytes outside
 * the carved `S` window are left untouched and remain the caller's.
 *
 * Does NOT write the ID word — that is the worker's responsibility at entry,
 * per the write protocol documented at the top of this header.
 *
 * @param region Caller-owned backing region (base + size).
 *
 * @kw allocator Allocator that owns the `n00b_callstack_t` bookkeeping struct
 *               and is recorded on the mmap registrations (defaults to the
 *               runtime allocator).
 *
 * @return The carved call stack on success, or an error code on failure:
 *         `N00B_ERR_CALLSTACK_REGION_UNUSABLE` for an undersized /
 *         un-alignable region, `N00B_ERR_CALLSTACK_PROTECT_FAILED` for a
 *         failed guard-band protect, or `N00B_ERR_CALLSTACK_REGISTER_FAILED`
 *         for a failed mmap-tree registration.  Stringify via
 *         `n00b_callstack_err_str`.
 *
 * @pre  Runtime is initialized (`n00b_page_size` is set); @p region.base is
 *       readable/writable for the full @p region.size span.
 * @post On success the carved usable region is registered as
 *       `n00b_mmap_stack`, the guard band is non-accessible, and the result's
 *       `caller_owned` flag is set.  The caller MUST keep the backing region
 *       alive until after the worker is joined, then free it itself.
 */
extern n00b_result_t(n00b_callstack_t *)
n00b_callstack_alloc_over(n00b_callstack_region_t region) _kargs
{
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Canonical O(1), lock-free SP -> region-base -> ID-word recovery.
 *
 * For an SP inside an `n00b_callstack_alloc` worker region, recovers the
 * region base by masking — `base = SP & ~(N00B_CALLSTACK_REGION_SIZE-1)`
 * — and returns the address of the ID word at the fixed offset
 * `N00B_CALLSTACK_REGION_SIZE - N00B_CALLSTACK_ID_WORD_SIZE` from the
 * base.  No mmap interval-tree lookup and no lock are taken (D-004,
 * D-014).
 *
 * This helper covers n00b worker callstacks ONLY.  The main thread's
 * kernel stack is not a power-of-2 region and is NOT handled here; its
 * O(1) recovery is a Phase-2 range check inside `n00b_thread_self()`
 * (D-014).
 *
 * @param sp              A stack pointer within a worker callstack region.
 * @param region_base_out If non-null, receives the masked region base.
 *
 * @return The address of the region's ID word.  This is computed purely
 *         from @p sp by masking, so a caller is responsible for only
 *         passing an SP that lives in a worker callstack region.
 */
extern uint64_t *
n00b_callstack_id_word(void *sp, void **region_base_out);

/**
 * @brief Look up a human-readable string for an `n00b_callstack_alloc` Err code.
 *
 * `n00b_callstack_alloc`'s Err channel carries either a negative
 * library-domain code (`N00B_ERR_CALLSTACK_*`) or a positive POSIX
 * `errno` surfaced verbatim from the underlying mmap/mprotect
 * primitives. This accessor (§5.5) covers both: a recognized domain
 * code returns its own description; any other value is folded through
 * `n00b_errno_str`, so a caller can stringify the Err channel without
 * first deciding which kind of code it holds.
 *
 * @param err  An Err code from `n00b_callstack_alloc` (either a negative
 *             `N00B_ERR_CALLSTACK_*` domain code or a POSIX `errno`).
 *
 * @return A non-null `n00b_string_t *` with a short description. The
 *         returned string is a rich-string literal with process-lifetime
 *         storage; the caller must NOT free it.
 */
extern n00b_string_t *
n00b_callstack_err_str(n00b_err_t err);
