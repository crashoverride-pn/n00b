#define N00B_MEM_INTERNAL_API
#define N00B_USE_INTERNAL_API

#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#endif
#include <assert.h>
#include <stdio.h>

#include "n00b.h"
#include "core/alloc_mdata.h"
#include "core/alloc.h"
#include "core/memory_info.h"
#include "core/mmaps.h"
#include "core/atomic.h"

/* Forward decl to avoid pulling in lock_common.h (and its
 * transitive thread-id dependency) at this layer. */
extern void n00b_lock_chains_scrub_range(uint64_t lo, uint64_t hi);
#include "adt/llstack.h"
#include "adt/list.h"
#include "core/align.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "util/math.h"

static inline void
pool_lock(n00b_pool_t *pool)
{
    while (n00b_atomic_or(&pool->lock, 1) != 0)
        ;
}

static inline void
pool_unlock(n00b_pool_t *pool)
{
    n00b_atomic_store(&pool->lock, 0);
}

// A pool's pages are registered in the global mmap tree (so
// n00b_mem_get_allocator / n00b_find_alloc_info can resolve an in-page
// pointer back to the pool — which is what makes n00b_free reclaim a
// pool allocation to its free list, and what lets the GC navigate it)
// when the pool is NOT __system AND either carries OOB metadata or is
// GC-visible (non-hidden):
//   - __system pools are bootstrap-critical (registering ctx->pool's
//     pages recurses through _n00b_alloc_raw) and are excluded.
//   - hidden, no-metadata pools are libn00b-internal, use only the
//     pool_free fast path, and never need address-to-allocator
//     resolution, so they stay out of the tree.
//   - everything else — external-metadata pools (incl. hidden ones like
//     user_pool) and plain non-hidden pools (e.g. a caller's claim pool)
//     — is registered so n00b_free works.
static inline bool
pool_pages_registered(n00b_allocator_t *alloc)
{
    return !alloc->__system
        && (alloc->metadata_pool != nullptr || !alloc->hidden);
}

static inline void *
new_page_entry(n00b_pool_t *pool, uint64_t *sz_ptr)
{
    uint64_t sz     = *sz_ptr;
    uint64_t hdr_sz = n00b_align(sizeof(n00b_pool_page_t));
    sz += hdr_sz;

    n00b_allocator_t *alloc      = (n00b_allocator_t *)pool;
    char             *name       = (char *)alloc->debug_name;
    uint64_t          aligned_sz = n00b_page_align(sz);
    /* skip_register=true puts the page back under pool control —
     * the matching @ref n00b_mmap_register_pool_page below decides
     * whether (and how) this page enters the global mmap tree.
     * The pool side wants this control so the unregister at free
     * time strictly precedes munmap (avoiding a window where a
     * concurrent GC mark scan can dereference a tree entry whose
     * backing page is no longer mapped). */
    auto mmap_r = n00b_mmap(aligned_sz,
                            .allocator     = alloc,
                            .name          = name,
                            .kind          = n00b_mmap_pool,
                            .skip_register = true);
    assert(n00b_result_is_ok(mmap_r));
    n00b_pool_page_t *cur = n00b_result_get(mmap_r);

    /* Register the page with the allocator so @ref n00b_mem_get_allocator
     * can resolve in-page pointers back to this pool, which is what
     * makes n00b_free → pool_free work (the address-to-allocator
     * lookup goes through the mmap tree).
     *
     * Only register hidden pools that have @c external_metadata.
     * Two distinct exclusions:
     *
     *  - @c __system pools (the mmap context's own backing @c ctx->pool
     *    and @c rt->system_pool) are bootstrap-critical: registering
     *    @c ctx->pool's pages here recurses infinitely
     *    (register_pool_page → mmaps_insert_raw → _n00b_alloc_raw →
     *    pool_alloc on ctx->pool → new_page_entry → back here).
     *
     *  - Non-metadata hidden pools (@c conduit_pool, per-thread
     *    @c ctx->pool, etc.) are libn00b-internal and exclusively use
     *    the @c pool_free fast path; their pages do not need
     *    address-to-allocator resolution.  Putting them in the global
     *    mmap tree adds GC-scan tree traversal load and a race window
     *    (concurrent @c pool_free → unregister → munmap vs GC mark
     *    iterator) for no benefit. */
    if (pool_pages_registered(alloc)) {
        (void)n00b_mmap_register_pool_page((void *)cur,
                                            (char *)cur + aligned_sz,
                                            alloc,
                                            name);
    }

    *sz_ptr   = aligned_sz - hdr_sz;
    cur->mapped_size = aligned_sz;
    void *res = (void *)cur + hdr_sz;

    pool_lock(pool);
    cur->next = pool->page_table;
    if (cur->next) {
        cur->next->prev = cur;
    }
    pool->page_table = cur;
    pool_unlock(pool);

    return res;
}

// Here, sz includes space for the n00b_pool_entry_t at the front.
static inline n00b_pool_entry_t *
big_mmap(n00b_pool_t *pool, uint64_t sz)
{
    n00b_pool_entry_t *entry = new_page_entry(pool, &sz);
    entry->list_index        = N00B_NUM_FREE_LISTS;

    /* Diagnostics: account for big-mmap allocations symmetrically
     * with delete_one_page_entry below so callers can verify the
     * fast path is balanced. */
    atomic_fetch_add(&pool->big_map_count, 1);

    return entry;
}

static inline void
delete_one_page_entry(n00b_pool_t *pool, n00b_pool_page_t *entry)
{
    pool_lock(pool);

    if (entry->prev) {
        entry->prev->next = entry->next;
    }
    else {
        assert(pool->page_table == entry);
        pool->page_table = entry->next;
    }

    if (entry->next) {
        entry->next->prev = entry->prev;
    }

    /* Capture mapped_size while we still hold the lock; the munmap
     * itself is fine to do unlocked once the page is unlinked. */
    size_t mapped = entry->mapped_size;

    pool_unlock(pool);

    /* Symmetric counterpart to new_page_entry's optional
     * @ref n00b_mmap_register_pool_page: pull the tree entry
     * BEFORE munmap so a concurrent GC mark pass can't follow a
     * stale interval-tree node into a no-longer-mapped page and
     * SIGBUS. The unregister is a no-op when the page was never
     * registered, so the check here mirrors the register-side gate
     * verbatim (skip @c __system bootstrap pools and skip pools
     * without @c external_metadata). */
    n00b_allocator_t *alloc = (n00b_allocator_t *)pool;
    if (pool_pages_registered(alloc)) {
        n00b_mmap_unregister((void *)entry);
    }

    /* Big-alloc free path: actually release the page back to the OS.
     * Without this the page stayed mapped until pool_destroy — any
     * pool client n00b_free-ing a >N00B_NUM_FREE_LISTS-class
     * allocation observed the slot count drop but RSS keep climbing. */
    if (mapped != 0) {
        n00b_safe_munmap((void *)entry, mapped);
        atomic_fetch_add(&pool->big_unmap_count, 1);
    }
}

static inline void *
add_page_to_list(n00b_pool_t *pool, uint64_t sz, n00b_llstack_t *stack)
{
    // Return one, and push the others to the free list.
    // Yes, we could pre-link the extras, but that's a PITA.
    uint64_t alloc_sz = n00b_page_size - n00b_align(sizeof(n00b_pool_page_t));
    void    *res      = new_page_entry(pool, &alloc_sz);

    assert(!(((uint64_t)sz) & 15));

    char    *p = ((char *)res) + n00b_align(sz);
    uint32_t n = (alloc_sz / n00b_align(sz));

    for (uint32_t i = 1; i < n; i++) {
        // Yes, we end up having to cast.
        n00b_llstack_node_t *node = (n00b_llstack_node_t *)p;
        p += n00b_align(sz);
        n00b_llstack_push_node(stack, node);
    }

    return res;
}

static void
pool_destroy(n00b_pool_t *pool)
{
    n00b_pool_page_t *entry = pool->page_table;
    n00b_pool_page_t *next;

    /* Scrub the lock chains FIRST, walking the page table, so that
     * the scrubber can chase chain links without ever reading from
     * a freed page.  Pool pages can hold n00b_mutex_t /
     * n00b_rwlock_t (e.g. as fields of an in-pool Regex), and
     * `n00b_lock_acquire_accounting` threads those onto each
     * thread's exclusive-lock chain.  The owning regex's teardown
     * destroys the pool without releasing them, so the chain would
     * otherwise be left with dangling pointers into freed memory. */
    n00b_pool_page_t *scrub = entry;
    while (scrub) {
        uintptr_t pg_lo = (uintptr_t)scrub;
        uintptr_t pg_hi = pg_lo + n00b_page_size;
        n00b_lock_chains_scrub_range(pg_lo, pg_hi);
        scrub = scrub->next;
    }

    /* If this pool's pages were registered in the global mmap tree,
     * pull each one out BEFORE munmap so a later n00b_mem_get_allocator
     * / GC mark can't follow a stale tree node into a freed page. */
    bool registered = pool_pages_registered((n00b_allocator_t *)pool);

    while (entry) {
        next = entry->next;
        /* Big-alloc pages can be larger than n00b_page_size — use the
         * captured mapped_size so we unmap the right region length. */
        size_t mapped = entry->mapped_size != 0 ? entry->mapped_size
                                                : n00b_page_size;
        if (registered) {
            n00b_mmap_unregister((void *)entry);
        }
        n00b_safe_munmap(entry, mapped);
        entry = next;
    }
}

static void
pool_free(n00b_pool_t *pool, void *ptr)
{
    n00b_pool_entry_t *entry = (n00b_pool_entry_t *)((char *)ptr - N00B_ALIGN);
    assert(entry->list_index <= N00B_NUM_FREE_LISTS);

    if (entry->list_index == N00B_NUM_FREE_LISTS) {
        /* `entry` sits at offset n00b_align(sizeof(n00b_pool_page_t))
         * past the page header (see `new_page_entry`).  Decrementing
         * a `n00b_pool_page_t *` by 1 only walks back
         * `sizeof(n00b_pool_page_t)` bytes, which is wrong when that
         * is smaller than N00B_ALIGN. */
        n00b_pool_page_t *page = (n00b_pool_page_t *)(((char *)entry)
                                                     - n00b_align(sizeof(n00b_pool_page_t)));
        delete_one_page_entry(pool, page);
        return;
    }

    unsigned int ix = entry->list_index;
    /* Entry size at bucket index ix is (1u << ix) << POST_ROUND_SHIFT
     * bytes — the same formula pool_alloc uses to derive ix from the
     * rounded size.  Earlier the memset used `ix << POST_ROUND_SHIFT`,
     * which under-zeros the tail of every bucket (and zeros 0 bytes
     * at ix=0); freshly-popped entries then return non-zero bytes,
     * silently violating the documented zero-fill contract. */
    memset(entry, 0, (1u << ix) << N00B_POST_ROUND_SHIFT);
    n00b_llstack_node_t *node_ptr = (n00b_llstack_node_t *)entry;

    n00b_llstack_push_node(&pool->free_lists[ix], node_ptr);
}

static void *
pool_alloc(n00b_pool_t *pool, uint64_t request, void *ignore)
{
    request += n00b_align(sizeof(n00b_pool_entry_t));

    uint64_t     sz = n00b_align_closest_pow2_ceil(request);
    unsigned int ix = n00b_int_log2(sz >> N00B_POST_ROUND_SHIFT);

    n00b_pool_entry_t *entry;

    if (ix >= N00B_NUM_FREE_LISTS) {
        entry = big_mmap(pool, request);
        ix    = N00B_NUM_FREE_LISTS;
    }
    else {
        n00b_llstack_t      *stack = &pool->free_lists[ix];
        n00b_llstack_node_t *nptr  = n00b_llstack_pop_node(stack);

        if (nptr) {
            entry = (n00b_pool_entry_t *)nptr;
        }
        else {
            entry = add_page_to_list(pool, sz, stack);
        }
    }

    entry->list_index = ix;
    void *p           = (void *)(((char *)entry) + N00B_ALIGN);

    assert(!(((uint64_t)p) & (N00B_ALIGN - 1)));
    return p;
}

uint64_t
n00b_pool_mapped_bytes(n00b_pool_t *pool)
{
    if (pool == nullptr) {
        return 0;
    }
    uint64_t          total = 0;
    n00b_pool_page_t *p;
    pool_lock(pool);
    for (p = pool->page_table; p != nullptr; p = p->next) {
        total += (uint64_t)p->mapped_size;
    }
    pool_unlock(pool);
    return total;
}

uint64_t
n00b_pool_big_map_count(n00b_pool_t *pool)
{
    return pool == nullptr ? 0 : atomic_load(&pool->big_map_count);
}

uint64_t
n00b_pool_big_unmap_count(n00b_pool_t *pool)
{
    return pool == nullptr ? 0 : atomic_load(&pool->big_unmap_count);
}

n00b_allocator_t *
n00b_pool_init(n00b_pool_t *pool) _kargs
{
    bool        __system          = false;
    bool        inline_headers    = false;
    bool        external_metadata = false;
    bool        hidden            = false;
    const char *name              = "pool";
}
{
    n00b_allocator_setup((n00b_allocator_t *)pool,
                         (n00b_calloc_fn)pool_alloc,
                         .free              = (n00b_free_fn)pool_free,
                         .destroy           = (n00b_allocator_destroy_fn)pool_destroy,
                         .name              = (char *)name,
                         .inline_headers    = inline_headers,
                         .external_metadata = external_metadata,
                         .hidden            = hidden,
                         .__system          = __system);

    pool->lock       = 0;
    pool->page_table = nullptr;

    for (int i = 0; i < N00B_NUM_FREE_LISTS; i++) {
        n00b_llstack_init(&pool->free_lists[i]);
    }

    /* Registration in rt->scannable_pools is handled by
     * n00b_allocator_setup (so both pools and arenas go through one
     * code path).  No additional bookkeeping here. */

    return (n00b_allocator_t *)pool;
}
