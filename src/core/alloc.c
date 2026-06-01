#include <stdio.h>
#include "n00b.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/alloc_mdata.h"
#include "adt/dict_untyped.h"
#include "core/mmaps.h"
#include "core/memory_info.h"
#include "core/stw.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "core/type_info.h"
#include "core/data_lock.h"
#include "util/assert.h"
#include "core/thread.h"

#ifndef N00B_METADATA_START_ENTRIES
#define N00B_METADATA_START_ENTRIES 1 << 12
#endif

extern uint64_t         n00b_gc_guard;
const n00b_alloc_opts_t _n00b_default_alloc_opts = {};
static void             n00b_run_and_remove_finalizers(void *ptr);

// The scoped allocator override is now a per-thread field reached via
// n00b_thread_self() (D-005), not a thread_local.  Before the runtime /
// calling thread is registered, self() is nullptr; the getter then
// reports "no override" and the setters/restores become no-ops, matching
// the startup-incomplete-window handling in src/core/data_lock.c.
n00b_allocator_t *
n00b_current_allocator(void)
{
    n00b_thread_t *self = n00b_thread_self();
    return self == nullptr ? nullptr : self->current_allocator;
}

n00b_allocator_t *
n00b_set_current_allocator(n00b_allocator_t *allocator)
{
    n00b_thread_t *self = n00b_thread_self();
    if (self == nullptr) {
        return nullptr;
    }

    n00b_allocator_t *previous = self->current_allocator;
    self->current_allocator    = allocator;
    return previous;
}

void
n00b_restore_current_allocator(n00b_allocator_t *previous)
{
    n00b_thread_t *self = n00b_thread_self();
    if (self == nullptr) {
        return;
    }
    self->current_allocator = previous;
}

n00b_allocator_scope_t
n00b_allocator_scope_enter(n00b_allocator_t *allocator)
{
    return (n00b_allocator_scope_t){
        .previous = n00b_set_current_allocator(allocator),
        .active   = true,
        .run      = true,
    };
}

void
n00b_allocator_scope_exit(n00b_allocator_scope_t *scope)
{
    if (!scope || !scope->active) {
        return;
    }

    n00b_restore_current_allocator(scope->previous);
    scope->active = false;
}

static inline void
n00b_alloc_add_inline_header(n00b_inline_hdr_t **hdrp,
                             size_t              alloc_len,
                             uint32_t            ptr_words,
                             bool                ptr_words_known,
                             uint64_t            type_hash,
                             bool                is_array,
                             bool                no_scan,
                             bool                mem_debug,
                             bool                mem_debug_taint)
{
    n00b_inline_hdr_t *hdr = *hdrp;
    assert(alloc_len >= sizeof(n00b_inline_hdr_t));

    *hdr = (n00b_inline_hdr_t){
        .guard           = n00b_gc_guard,
        .tinfo           = type_hash,
        .alloc_len       = alloc_len,
        .ptr_words       = ptr_words,
        .ptr_words_known = ptr_words_known,
        .is_array        = is_array,
        .no_scan         = no_scan,
        .mem_debug       = mem_debug,
        .mem_debug_taint = mem_debug_taint,
    };

    *hdrp = ++hdr;
}

void *
_n00b_alloc_raw(size_t             n,
                size_t             sz,
                uint64_t           type_hash,
                const char        *location,
                n00b_alloc_opts_t *opts,
                +) _kargs: opaque
{
    n00b_inline_hdr_t *hdr      = nullptr;
    n00b_oob_hdr_t    *map_item = nullptr;
    n00b_alloc_opts_t  local_opts;

    if (!opts) {
        local_opts = _n00b_default_alloc_opts;
        opts       = &local_opts;
    }

    n00b_ensure_allocator(opts->allocator);

    if (!opts->allocator->__system) {
        n00b_thread_checkin();
    }

    /* D-049: upgrade a DEFAULT-scanned typed allocation to a precise
     * CALLBACK scan when a link-time GC-map descriptor is registered for
     * its type. Only when the caller specified no scan policy of its own
     * (DEFAULT + no scan_cb) and the allocator carries OOB metadata —
     * CALLBACK needs the metadata path to survive compaction (see the
     * assert below); allocators without it keep the conservative DEFAULT
     * scan, which is correct for the GC and only those metadata-backed
     * objects are ever marshaled. The descriptor's element count is
     * derived from the allocation length by n00b_gc_scan_cb_type_layout,
     * so one shared per-type descriptor serves both n (=1) and arrays. */
    if (opts->scan_kind == N00B_GC_SCAN_KIND_DEFAULT
        && opts->scan_cb == nullptr
        && type_hash != 0
        && opts->allocator->metadata_pool != nullptr) {
        const n00b_gc_struct_layout_t *layout = n00b_gc_type_map_lookup(type_hash);
        if (layout != nullptr) {
            opts->scan_kind = N00B_GC_SCAN_KIND_CALLBACK;
            opts->scan_cb   = n00b_gc_scan_cb_type_layout;
            opts->scan_user = (void *)layout;
        }
    }

    /* Map scan_kind == NONE onto the legacy no_scan switch so the GC's
     * worklist add-path (which checks no_scan) skips scanning this
     * allocation. */
    if (opts->scan_kind == N00B_GC_SCAN_KIND_NONE) {
        opts->no_scan = true;
    }
    /* CALLBACK requires the OOB-metadata path so scan_cb / scan_user
     * survive forwarding (the inline header has no room for the cb
     * pointer reliably across compaction). */
    if (opts->scan_kind == N00B_GC_SCAN_KIND_CALLBACK
        && opts->allocator->metadata_pool == nullptr) {
        assert(opts->allocator->metadata_pool != nullptr
               && "scan_kind=CALLBACK requires an allocator with OOB metadata");
    }

    uint64_t request  = n * sz;
    uint64_t user_words = request / sizeof(void *);
    n00b_require(user_words <= UINT32_MAX,
                 "allocation logical pointer words exceed metadata capacity");
    uint32_t ptr_words = (uint32_t)user_words;
    bool     is_array = n > 1;

    if (opts->allocator->add_inline_header) {
        request += N00B_ALLOC_HDR_SZ;
    }
    void *r;

    if (!request) {
        request = opts->allocator->add_inline_header ? sizeof(n00b_inline_hdr_t) : 1;
    }

    request = n00b_align(request);

    // Currently never pass parameters to the allocator. For future use.
    r = (*opts->allocator->zero_alloc)(opts->allocator, request, nullptr);

    if (opts->allocator->add_inline_header) {
        hdr = r;

        n00b_alloc_add_inline_header((n00b_inline_hdr_t **)&r,
                                     request,
                                     ptr_words,
                                     true,
                                     type_hash,
                                     n > 1,
                                     opts->no_scan,
                                     opts->mem_debug,
                                     opts->debug_taint);
    }

    if (opts->allocator->metadata_pool != nullptr) {
        n00b_alloc_opts_t md_opts = {.allocator = opts->allocator->metadata_pool};
        map_item                  = n00b_alloc_with_opts(n00b_oob_hdr_t, &md_opts);

        /* Seed the OOB liveness state. `alive` flags this slot as
         * handed out so the GC mark/sweep treats it as a root and a
         * non-leak. The epoch is stamped to the runtime's current
         * value so a collection running between this alloc and the
         * caller's first use cannot misclassify it as stale. */
        uint64_t epoch_now = 0;
        {
            n00b_runtime_t *rt = n00b_get_runtime();
            if (rt) {
                epoch_now = n00b_atomic_load(&rt->gc_current_epoch);
            }
        }

        *map_item = (n00b_oob_hdr_t){
            .user_ptr        = r,
            .tinfo           = type_hash,
            .alloc_len       = request,
            .ptr_words       = ptr_words,
            .ptr_words_known = true,
            .is_array        = n > 1,
            .no_scan         = opts->no_scan,
            .mem_debug       = opts->mem_debug,
            .mem_debug_taint = opts->debug_taint,
            .scan_kind       = opts->scan_kind,
            .scan_cb         = opts->scan_cb,
            .scan_user       = opts->scan_user,
            .hcur            = hdr,
            .file_name       = location,
            .gc_epoch        = epoch_now,
            .alive           = 1,
        };

        n00b_dict_untyped_put(opts->allocator->metadata, r, map_item);
        assert(n00b_dict_untyped_get(opts->allocator->metadata, r, nullptr) == map_item);
    }

    // If the allocator has no headers and no metadata but is visible to
    // the GC (non-hidden), register the allocation in the range tree so
    // the collector's fallback path can discover and scan it.
    if (!opts->allocator->hidden && !opts->allocator->add_inline_header
        && opts->allocator->metadata_pool == nullptr
        && n00b_option_is_set(n00b_default_runtime)) {
        n00b_mmap_register_range(r,
                                 (char *)r + request,
                                 n00b_mmap_pool,
                                 .allocator = opts->allocator,
                                 .scan_kind = opts->scan_kind,
                                 .scan_cb   = opts->scan_cb,
                                 .scan_user = opts->scan_user);
    }

    assert(!(((uint64_t)r) & (N00B_ALIGN - 1)));

    // Dispatch the vtable constructor if the type is registered.
    // Guard on startup_complete to avoid early-init lookups.
    //
    // Constructor dispatch depends on type_info flags:
    //   !ctor_takes_kargs && !ctor_takes_vargs: ctor(self)
    //   ctor_takes_kargs  && !ctor_takes_vargs: ctor(self, kargs_ptr)
    //   ctor_takes_vargs:                       ctor(self, vargs, kargs_ptr)
    //
    // For kargs/vargs constructors, the data comes from vargs packed
    // by n00b_new_kargs / n00b_new_both.  If no vargs were provided,
    // kargs/vargs constructors are skipped (use n00b_new_kargs to
    // trigger construction, not bare n00b_alloc).
    if (!is_array && type_hash && n00b_option_is_set(n00b_default_runtime)
        && n00b_get_runtime()->startup_complete) {
        auto tinfo_opt = n00b_type_lookup(type_hash);

        if (n00b_option_is_set(tinfo_opt)) {
            n00b_type_info_t *tinfo = n00b_option_get(tinfo_opt);
            n00b_vtable_entry ctor  = tinfo->core_vtable[N00B_BI_CONSTRUCTOR];
            if (ctor) {
                bool have_vargs = vargs && vargs->nargs > 0;

                if (tinfo->ctor_takes_vargs && have_vargs) {
                    // ctor(self, vargs, kargs).
                    // n00b_new_both packs: real_varg0, ..., kargs_ptr
                    // kargs is always the last varg.
                    void *ctor_kargs = vargs->args[vargs->nargs - 1];
                    vargs->nargs--;
                    ((void (*)(void *, n00b_vargs_t *, void *))ctor)(
                        r, vargs, ctor_kargs);
                }
                else if (tinfo->ctor_takes_kargs && !tinfo->ctor_takes_vargs) {
                    // ctor(self, kargs).
                    // kargs comes from the opaque _kargs parameter.
                    if (kargs) {
                        ((void (*)(void *, void *))ctor)(r, kargs);
                    }
                }
                else if (!tinfo->ctor_takes_kargs && !tinfo->ctor_takes_vargs) {
                    // ctor(self) — always dispatched (no data needed).
                    ((void (*)(void *))ctor)(r);
                }
            }
        }
    }

    if (opts->finalizer) {
        n00b_runtime_t *rt = n00b_get_runtime();
        if (rt) {
            // Prefer the OOB record when this pool has one
            // (external_metadata = true). The inline header is
            // intentionally not used for finalizer storage — see
            // n00b_add_finalizer for the rationale.
            n00b_oob_hdr_t *meta_oob =
                (opts->allocator->metadata_pool != nullptr) ? map_item : nullptr;

            if (meta_oob != nullptr) {
                meta_oob->finalizer      = opts->finalizer;
                meta_oob->finalizer_user = opts->finalizer_data;
            }
            else {
                n00b_alloc_opts_t     md_opts = {.allocator = (n00b_allocator_t *)&rt->system_pool};
                n00b_finalizer_info_t *info  = n00b_alloc_with_opts(n00b_finalizer_info_t, &md_opts);

                *info = (n00b_finalizer_info_t){
                    .funcptr    = opts->finalizer,
                    .key        = r,
                    .alloc_info = nullptr,
                    .user_ptr   = opts->finalizer_data,
                };
                n00b_list_push(rt->finalizers, info);
            }
        }
    }

    return r;
}

void
n00b_allocator_setup(n00b_allocator_t *allocator, n00b_calloc_fn alloc) _kargs
{
    n00b_free_fn              free              = nullptr;
    n00b_allocator_destroy_fn destroy           = nullptr;
    const char               *name              = nullptr;
    bool                      inline_headers    = true;
    bool                      external_metadata = true;
    // RISKY for custom allocators. Hides from GC.
    bool                      hidden            = false;
    // DO NOT USE for custom allocators. Skips mmaps.
    bool                      __nomap           = false;
    // DO NOT USE for custom allocators. Skips STW check.
    bool                      __system          = false;
    bool                      __is_md_pool      = false;
}
{
    (void)__nomap;
    n00b_allocator_t *md_pool = nullptr;

    if (external_metadata) {
        md_pool = (n00b_allocator_t *)n00b_new_arena(.no_map         = true,
                                                     .__system       = true,
                                                     .hidden         = true,
                                                     .use_gc         = false,
                                                     .inline_headers = false,
                                                     .name           = "md_pool");
    }

    n00b_dict_untyped_t *md = nullptr;

    if (external_metadata) {
        md = n00b_alloc_with_opts(n00b_dict_untyped_t, &(n00b_alloc_opts_t){.allocator = md_pool});
    }

    *allocator = (n00b_allocator_t){
        .zero_alloc        = alloc,
        .free              = free,
        .destroy           = destroy,
        .debug_name        = name,
        .add_inline_header = inline_headers,
        .__system          = __system,
        .__md_pool         = __is_md_pool,
        .hidden            = hidden,
        .metadata_pool     = md_pool,
        .metadata          = md,
    };

    if (external_metadata) {
        n00b_dict_untyped_init(allocator->metadata,
                               .start_capacity = N00B_METADATA_START_ENTRIES,
                               .allocator      = allocator->metadata_pool,
                               .hash           = n00b_hash_word,
                               .skip_obj_hash  = true);

        /* Register with the runtime so the GC mark phase walks this
         * pool's per-alloc metadata. Skip md_pool allocators (their
         * own backing storage); the metadata dict for those is the
         * pool we'd be registering, which would close a cycle. */
        if (!__is_md_pool) {
            n00b_runtime_t *rt = n00b_get_runtime();
            if (rt && rt->metadata_pools.data) {
                n00b_list_push(rt->metadata_pools, allocator);
            }
        }
    }
}

void
n00b_free(void *ptr)
{
    /* STW handshake at the top: if a collect is in flight (some
     * other thread called n00b_stop_the_world), block here before
     * touching any allocator state. Without this, a foreign thread
     * (e.g. an XPC / libdispatch worker that attached to the
     * runtime via n00b_thread_init but didn't pass through
     * n00b_thread_checkin on the way in) can walk into pool_free /
     * delete_one_page_entry while the GC mark phase is reading the
     * mmap tree, then mutate the tree or munmap the page
     * underneath the mark scanner. The free hot path on
     * hidden+metadata pools doesn't go through _n00b_alloc_raw's
     * checkin, so this is the one chokepoint that catches every
     * external-thread free.
     *
     * Cheap when no STW is in flight (one atomic load on
     * self_lock; checkin short-circuits on 0). Safe to call before
     * any ptr / allocator validation below — n00b_thread_checkin
     * doesn't touch ptr. */
    n00b_thread_checkin();

    n00b_run_and_remove_finalizers(ptr);

    n00b_allocator_opt_t alloc_opt = n00b_mem_get_allocator(ptr);

    if (!n00b_option_is_set(alloc_opt)) {
        return;
    }

    n00b_allocator_t *allocator = n00b_option_get(alloc_opt);

    if (!allocator->free) {
        return;
    }

    // Remove the range-tree entry for headerless non-hidden allocations
    // (the mirror of the registration in _n00b_alloc_raw).
    if (!allocator->hidden && !allocator->add_inline_header
        && allocator->metadata_pool == nullptr) {
        n00b_runtime_t  *rt   = n00b_get_runtime();
        n00b_mmap_ctx_t *mctx = n00b_global_mem_map(rt);
        n00b_mmap_delete_ranges(mctx, (uint64_t)ptr, (uint64_t)ptr + 1);
    }

    /* Tear down the OOB metadata for this allocation before we
     * hand the memory back to the allocator. Three things have to
     * happen, in order, atomically with respect to the GC mark/
     * sweep:
     *
     *   1. clear @c alive — the source of truth for the GC's
     *      "this slot is handed out" view; the metadata-pool sweep
     *      depends on it for leak classification.
     *   2. clear @c finalizer — defangs the order-dependent free
     *      chain that the leak detector's per-bucket sweep can
     *      trigger when both halves of an owned pair (e.g. the wax
     *      payload msg + buffer) are flagged as leaks in the same
     *      pass. Without this, processing the msg's slot would
     *      call its finalizer (= n00b_free(buffer)) on an already-
     *      reclaimed buffer.
     *   3. remove the dict entry and free the OOB record itself.
     *      Otherwise the metadata dict and its md_pool slots leak
     *      monotonically — n00b_free returns the user allocation
     *      but the per-allocation bookkeeping accumulates forever,
     *      which masks bona-fide leak fixes.
     */
    if (allocator->metadata_pool != nullptr) {
        n00b_oob_hdr_t *oob = n00b_dict_untyped_get(allocator->metadata,
                                                   ptr,
                                                   nullptr);
        if (oob) {
            oob->alive          = 0;
            oob->finalizer      = nullptr;
            oob->finalizer_user = nullptr;
            (void)n00b_dict_untyped_remove(allocator->metadata, ptr);
            n00b_free(oob);
        }
    }

    if (allocator->add_inline_header) {
        ptr = (char *)ptr - N00B_ALLOC_HDR_SZ;
    }

    (*allocator->free)(allocator, ptr);
}

void
n00b_add_finalizer(void *obj, n00b_finalizer_t fn, void *user_data)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    assert(rt);

    // Primary storage: write the finalizer directly into the
    // allocation's out-of-band record (when one exists). The OOB
    // record is the authoritative dynamic metadata and not on the
    // marshal path, so it's the safe place to attach runtime state
    // like this. n00b_run_and_remove_finalizers does a single
    // pointer dereference to read it back — O(1), no global walk.
    //
    // Inline-only allocations deliberately stay on the fallback
    // path; the inline header doubles as the marshal payload and
    // must stay tight.
    n00b_alloc_info_t ainfo = n00b_find_alloc_info(obj);
    if (ainfo.kind == n00b_alloc_oob) {
        ainfo.hdr.oob->finalizer      = fn;
        ainfo.hdr.oob->finalizer_user = user_data;
        return;
    }

    // Fallback: allocations from pools without metadata records
    // (e.g. the hidden system_pool, which is intentionally minimal)
    // register in the global list keyed on the user pointer. Slower
    // O(N) lookup, but rare — system_pool allocations are GC infra,
    // not application data.
    n00b_allocator_t      *sp   = (n00b_allocator_t *)&rt->system_pool;
    n00b_finalizer_info_t *info = n00b_alloc_with_opts(n00b_finalizer_info_t, &(n00b_alloc_opts_t){.allocator = sp});

    *info = (n00b_finalizer_info_t){
        .funcptr    = fn,
        .key        = obj,
        .alloc_info = nullptr,
        .user_ptr   = user_data,
    };

    n00b_list_push(rt->finalizers, info);
}

static void
n00b_run_and_remove_finalizers(void *ptr)
{
    if (!n00b_option_is_set(n00b_default_runtime)) {
        return;
    }

    n00b_runtime_t *rt = n00b_get_runtime();
    if (!rt) {
        goto type_cleanup;
    }

    // Fast path: read the finalizer slot from the allocation's
    // out-of-band record. Clear the slot before invoking so a
    // finalizer that frees other memory cannot trigger a recursive
    // run against the same allocation. OOB-bearing allocations
    // cannot ALSO have a global list entry (n00b_add_finalizer
    // chooses one path or the other), so this path is complete.
    {
        n00b_alloc_info_t ainfo = n00b_find_alloc_info(ptr);
        if (ainfo.kind == n00b_alloc_oob) {
            n00b_finalizer_t fn           = ainfo.hdr.oob->finalizer;
            void            *user         = ainfo.hdr.oob->finalizer_user;
            ainfo.hdr.oob->finalizer      = nullptr;
            ainfo.hdr.oob->finalizer_user = nullptr;
            if (fn) {
                fn(user);
            }
            goto type_cleanup;
        }
    }

    // Fallback: walk the global list for allocations from pools
    // without metadata records (system_pool). Match by user pointer.
    if (!rt->finalizers.data) {
        goto type_cleanup;
    }
    {
        // Walk backwards for safe removal via n00b_list_delete.
        size_t len = n00b_list_len(rt->finalizers);

        for (size_t i = len; i > 0; i--) {
            n00b_finalizer_info_t *entry = n00b_list_get(rt->finalizers, i - 1);

            if (entry->key == ptr) {
                entry->funcptr(entry->user_ptr);
                (void)n00b_list_delete(rt->finalizers, i - 1);
                n00b_free(entry);
            }
        }
    }

type_cleanup:;
    // Lock cleanup and vtable destructor via the type registry.
    auto tinfo_opt = n00b_type_info_for(ptr);
    if (!n00b_option_is_set(tinfo_opt)) {
        return;
    }
    n00b_type_info_t *tinfo = n00b_option_get(tinfo_opt);

    // Free the lock if the type has a registered lock_offset.  Guard
    // the deref: with external_metadata pools, tinfo is set even for
    // pool allocs whose user_ptr offset doesn't actually point to a
    // heap-allocated lock pointer (the type may have been allocated
    // raw into pool memory without n00b_*_init populating .lock).
    // Confirm `*lock_ptr` resolves to a tracked allocation header
    // before freeing.
    if (n00b_option_is_set(tinfo->lock_offset)) {
        uint32_t        offset   = n00b_option_get(tinfo->lock_offset);
        n00b_rwlock_t **lock_ptr = (n00b_rwlock_t **)((char *)ptr + offset);
        n00b_rwlock_t  *lock_val = *lock_ptr;
        if (lock_val) {
            n00b_alloc_info_t lock_info = n00b_find_alloc_info(lock_val);
            if (n00b_alloc_info_is_heap(lock_info)) {
                n00b_free(lock_val);
            }
            *lock_ptr = nullptr;
        }
    }

    // Run the vtable destructor.
    n00b_vtable_entry dtor = tinfo->core_vtable[N00B_BI_FINALIZER];
    if (dtor) {
        ((void (*)(void *))dtor)(ptr);
    }
}

void
n00b_allocator_destroy(n00b_allocator_t *allocator)
{
    if (allocator->metadata_pool) {
        // Sample the `__md_pool` flag *before* the recursive destroy:
        // arena/pool destroys can unmap the struct itself, so reading
        // through the pointer afterwards is a use-after-free.
        bool was_md_pool = allocator->metadata_pool->__md_pool;
        n00b_allocator_t *md = allocator->metadata_pool;
        n00b_allocator_destroy(md);
        if (was_md_pool) {
            free(md);
        }
        allocator->metadata_pool = nullptr;
    }

    (*allocator->destroy)(allocator);
}

#define find_sentinal(p, s) _find_sentinal(((uint64_t)p), ((uint64_t *)s))

static inline char *
_find_sentinal(uint64_t p_num, uint64_t *start)
{
    uint64_t *p = (uint64_t *)n00b_align_floor(p_num, sizeof(void *));

    while (p >= start) {
        if (*p == n00b_gc_guard) {
            return (char *)p;
        }
        p--;
    }

    return nullptr;
}

// Returns the most authoritative header, unless prefer_inline is set,
// in which case it'll return the inline header.
//
// If you need to know if it's an out-of-heap pointer so you can cast it,
// then provide is_metadata_header.
//
// Returns nullptr if not found. This obviously should all change to
// return a variant, once I revisit variants.

void
_n00b_find_alloc_info(void *addr, n00b_alloc_info_t *result) _kargs
{
    n00b_allocator_t *allocator       = nullptr;
    bool              scan_for_header = false;
}
{
    auto  mmap_opt = n00b_mmap_by_address(addr);
    char *p        = (char *)addr;

    if (!n00b_option_is_set(mmap_opt)) {
        *result = (n00b_alloc_info_t){.kind = n00b_alloc_none};
        return;
    }

    n00b_mmap_info_t *mmap = n00b_option_get(mmap_opt);
    n00b_allocator_t *al   = mmap->allocator;
    switch (mmap->kind) {
    case n00b_mmap_static: {
        auto range_opt = n00b_mmap_range_by_address(addr);
        if (!n00b_option_is_set(range_opt)) {
            break;
        }
        *result = (n00b_alloc_info_t){
            .kind      = n00b_alloc_static_range,
            .hdr.range = n00b_option_get(range_opt),
        };
        return;
    }
    case n00b_mmap_pool:
    case n00b_mmap_managed_segment:
    case n00b_mmap_sys_segment:

        if (al->add_inline_header) {
            p -= N00B_ALLOC_HDR_SZ;
        }

        if (scan_for_header && al->add_inline_header) {
            char *scan_ptr = find_sentinal(p, (char *)mmap->start);

            if (!scan_ptr) {
                break;
            }

            p    = scan_ptr;
            addr = scan_ptr + N00B_ALLOC_HDR_SZ;
        }

        if (al->metadata) {
            n00b_oob_hdr_t *oob = n00b_dict_untyped_get(al->metadata, addr, nullptr);
            if (!oob) {
                *result = (n00b_alloc_info_t){.kind = n00b_alloc_err};
                return;
            }
            *result = (n00b_alloc_info_t){
                .kind    = n00b_alloc_oob,
                .hdr.oob = oob,
            };
            return;
        }

        n00b_inline_hdr_t *hdr = (n00b_inline_hdr_t *)p;

        if (((uint64_t)p) < mmap->start || hdr->guard != n00b_gc_guard) {
            *result = (n00b_alloc_info_t){.kind = n00b_alloc_err};
            return;
        }
        *result = (n00b_alloc_info_t){
            .kind        = n00b_alloc_inline,
            .hdr.in_line = hdr,
        };
        return;

    default:
        break;
    }
    *result = (n00b_alloc_info_t){.kind = n00b_alloc_none};
    return;
}

n00b_option_t(n00b_inline_hdr_t *) n00b_object_header(void *p)
{
    n00b_alloc_info_t info = n00b_find_alloc_info(p);

    if (!n00b_alloc_info_is_heap(info)) {
        return n00b_option_none(n00b_inline_hdr_t *);
    }

    if (!n00b_alloc_info_is_oob(info)) {
        return n00b_alloc_info_inline(info);
    }

    n00b_oob_hdr_t *oob = info.hdr.oob;
    if (!oob->hcur) {
        return n00b_option_none(n00b_inline_hdr_t *);
    }
    return n00b_option_set(n00b_inline_hdr_t *, oob->hcur);
}
