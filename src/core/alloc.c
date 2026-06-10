#include <stdio.h>
#include "n00b.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/alloc_mdata.h"
#include "adt/dict.h"
#include "adt/dict_untyped.h"
#include "core/mmaps.h"
#include "core/memory_info.h"
#include "core/rwlock.h"
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

// Every external-metadata allocator stores its dict in an attached metadata
// arena. Any dict access must drain before STW may inspect or swap that arena.
static inline bool
n00b_allocator_metadata_needs_stw_gate(n00b_allocator_t *al)
{
    n00b_runtime_t *rt = n00b_get_runtime();

    return al && al->metadata_pool != nullptr && !al->__system
        && rt != nullptr && rt->critical_execution.inited
        && !n00b_atomic_load(&rt->stw_active);
}

static inline void
n00b_metadata_gate_unlock(bool unlock_gate)
{
    if (unlock_gate) {
        n00b_rw_unlock(&n00b_get_runtime()->critical_execution);
    }
}

static inline n00b_oob_hdr_t *
n00b_oob_for_user_ptr_held(void *ptr, bool *unlock_gate)
{
    if (unlock_gate != nullptr) {
        *unlock_gate = false;
    }

    n00b_allocator_opt_t alloc_opt = n00b_mem_get_allocator(ptr);
    if (!n00b_option_is_set(alloc_opt)) {
        return nullptr;
    }

    n00b_allocator_t *allocator = n00b_option_get(alloc_opt);
    if (allocator == nullptr || allocator->metadata == nullptr) {
        return nullptr;
    }

    bool md_stw = n00b_allocator_metadata_needs_stw_gate(allocator);
    if (md_stw) {
        n00b_rw_read_lock(&n00b_get_runtime()->critical_execution);
        if (unlock_gate != nullptr) {
            *unlock_gate = true;
        }
    }

    return n00b_dict_untyped_get(allocator->metadata, ptr, nullptr);
}

static n00b_allocator_t *
n00b_new_metadata_pool(void)
{
    return (n00b_allocator_t *)n00b_new_arena(.no_map         = true,
                                              .__system       = true,
                                              .hidden         = true,
                                              .use_gc         = false,
                                              .inline_headers = false,
                                              .name           = "md_pool");
}

static uint32_t
n00b_metadata_start_capacity(uint64_t records)
{
    uint64_t result = records * 2u;

    if (result < N00B_METADATA_START_ENTRIES) {
        result = N00B_METADATA_START_ENTRIES;
    }
    if (result > UINT32_MAX) {
        result = UINT32_MAX;
    }

    return (uint32_t)result;
}


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

    // No cooperative STW check-in on the alloc hot path (WP-001): the collector
    // preempts mutators (it does not wait for them to self-park at an
    // allocation), so an allocating thread no longer needs to poll for a stop.

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
     * survive forwarding. If a caller explicitly asks for CALLBACK on an
     * allocator that cannot store the callback metadata, fall back to the
     * conservative DEFAULT scan instead of aborting the process. */
    if (opts->scan_kind == N00B_GC_SCAN_KIND_CALLBACK
        && opts->allocator->metadata_pool == nullptr) {
        opts->scan_kind = N00B_GC_SCAN_KIND_DEFAULT;
        opts->scan_cb   = nullptr;
        opts->scan_user = nullptr;
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
        bool md_stw = n00b_allocator_metadata_needs_stw_gate(opts->allocator);
        if (md_stw) {
            n00b_rw_read_lock(&n00b_get_runtime()->critical_execution);
        }

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
        if (md_stw) {
            n00b_rw_unlock(&n00b_get_runtime()->critical_execution);
        }
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
        md_pool = n00b_new_metadata_pool();
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

        /* NOTE: external_metadata allocators are deliberately NOT
         * auto-registered in rt->metadata_pools. That list means
         * "treat every alive record as a GC root" (n00b_scan_metadata_pools)
         * — appropriate only for the never-collected "array" pools, of
         * which there are currently none. Registering every
         * external_metadata allocator here pinned GC ARENAS' allocations
         * as roots, defeating arena collection (a moving arena kept ~60%
         * of dead allocs alive; with the metadata-pool root pass skipped
         * it collected to zero). Nothing is registered by default; an
         * array pool that needs root semantics must opt in explicitly.
         * (void)__is_md_pool keeps the parameter live. */
        (void)__is_md_pool;
    }
}

void
n00b_allocator_compact_metadata(n00b_allocator_t *allocator)
{
    if (allocator == nullptr || allocator->metadata_pool == nullptr
        || allocator->metadata == nullptr) {
        return;
    }

    n00b_runtime_t *rt          = n00b_get_runtime();
    bool            unlock_gate = false;

    if (rt != nullptr && rt->critical_execution.inited
        && !n00b_atomic_load(&rt->stw_active)) {
        n00b_rw_write_lock(&rt->critical_execution);
        unlock_gate = true;
    }

    n00b_dict_untyped_t       *old_md   = allocator->metadata;
    n00b_allocator_t          *old_pool = allocator->metadata_pool;
    n00b_dict_untyped_store_t *store    = n00b_atomic_load(&old_md->store);

    if (store == nullptr) {
        if (unlock_gate) {
            n00b_rw_unlock(&rt->critical_execution);
        }
        return;
    }

    uint64_t records = 0;
    for (uint32_t i = 0; i <= store->last_slot; i++) {
        n00b_dict_untyped_bucket_t *bucket = &store->buckets[i];
        if (bucket->key == nullptr) {
            continue;
        }
        if (n00b_atomic_load(&bucket->flags) & N00B_HT_FLAG_DELETED) {
            continue;
        }
        n00b_oob_hdr_t *oob = (n00b_oob_hdr_t *)bucket->value;
        if (oob != nullptr && oob->alive) {
            records++;
        }
    }

    n00b_allocator_t    *new_pool = n00b_new_metadata_pool();
    n00b_dict_untyped_t *new_md
        = n00b_alloc_with_opts(n00b_dict_untyped_t,
                               &(n00b_alloc_opts_t){.allocator = new_pool});

    n00b_dict_untyped_init(new_md,
                           .start_capacity = n00b_metadata_start_capacity(records),
                           .allocator      = new_pool,
                           .hash           = n00b_hash_word,
                           .skip_obj_hash  = true);

    for (uint32_t i = 0; i <= store->last_slot; i++) {
        n00b_dict_untyped_bucket_t *bucket = &store->buckets[i];
        if (bucket->key == nullptr) {
            continue;
        }
        if (n00b_atomic_load(&bucket->flags) & N00B_HT_FLAG_DELETED) {
            continue;
        }
        n00b_oob_hdr_t *old_oob = (n00b_oob_hdr_t *)bucket->value;
        if (old_oob == nullptr || !old_oob->alive) {
            continue;
        }

        n00b_oob_hdr_t *new_oob
            = n00b_alloc_with_opts(n00b_oob_hdr_t,
                                   &(n00b_alloc_opts_t){.allocator = new_pool});
        *new_oob = *old_oob;
        n00b_dict_untyped_put(new_md, bucket->key, new_oob);
    }

    allocator->metadata_pool = new_pool;
    allocator->metadata      = new_md;

    n00b_allocator_destroy(old_pool);

    if (unlock_gate) {
        n00b_rw_unlock(&rt->critical_execution);
    }
}

void
n00b_free(void *ptr)
{
    /* No cooperative STW handshake here (WP-001).  The old concern was a
     * foreign thread walking into pool_free / delete_one_page_entry — mutating
     * the mmap tree or munmap'ing a page — while the GC mark phase read the tree
     * under a cooperative stop.  That is now closed structurally: munmap and
     * every mmap interval-tree mutation are CRITICAL EXECUTION held under
     * rt->critical_execution, and a stop-the-world initiator must ACQUIRE that
     * gate before it suspends any thread.  So the collector can never be mid-walk
     * while a free mutates the tree underneath it, with no per-free poll. */
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
     *   3. remove the dict entry. The OOB record lives in the
     *      allocator's attached metadata arena; it is reclaimed when
     *      that metadata arena is compacted/replaced wholesale.
     */
    if (allocator->metadata_pool != nullptr) {
        // Metadata teardown runs under the STW read lock so any destructive
        // metadata-arena rebuild first drains in-flight dict mutation.
        bool md_stw = n00b_allocator_metadata_needs_stw_gate(allocator);
        if (md_stw) {
            n00b_rw_read_lock(&n00b_get_runtime()->critical_execution);
        }
        n00b_oob_hdr_t *oob = n00b_dict_untyped_get(allocator->metadata,
                                                   ptr,
                                                   nullptr);
        if (oob) {
            oob->alive          = 0;
            oob->finalizer      = nullptr;
            oob->finalizer_user = nullptr;
            (void)n00b_dict_untyped_remove(allocator->metadata, ptr);
        }
        if (md_stw) {
            n00b_rw_unlock(&n00b_get_runtime()->critical_execution);
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
    bool            unlock_gate = false;
    n00b_oob_hdr_t *oob         = n00b_oob_for_user_ptr_held(obj, &unlock_gate);
    if (oob != nullptr) {
        oob->finalizer      = fn;
        oob->finalizer_user = user_data;
        n00b_metadata_gate_unlock(unlock_gate);
        return;
    }
    n00b_metadata_gate_unlock(unlock_gate);

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
        bool            unlock_gate = false;
        n00b_oob_hdr_t *oob         = n00b_oob_for_user_ptr_held(ptr, &unlock_gate);
        if (oob != nullptr) {
            n00b_finalizer_t fn   = oob->finalizer;
            void            *user = oob->finalizer_user;
            oob->finalizer      = nullptr;
            oob->finalizer_user = nullptr;
            n00b_metadata_gate_unlock(unlock_gate);
            if (fn) {
                fn(user);
            }
            goto type_cleanup;
        }
        n00b_metadata_gate_unlock(unlock_gate);
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
        // The metadata pool is an arena; its own destroy
        // (n00b_arena_delete) unmaps the arena struct itself, so there
        // is nothing to release through the pointer afterwards.
        n00b_allocator_destroy(allocator->metadata_pool);
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

[[n00b::nogc]] void
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
            // Metadata reads take the STW read lock too: this same dict can be
            // rebuilt wholesale by the owning allocator's metadata compactor.
            bool md_stw = n00b_allocator_metadata_needs_stw_gate(al);
            if (md_stw) {
                n00b_rw_read_lock(&n00b_get_runtime()->critical_execution);
            }
            n00b_oob_hdr_t *oob = n00b_dict_untyped_get(al->metadata, addr, nullptr);
            if (md_stw) {
                n00b_rw_unlock(&n00b_get_runtime()->critical_execution);
            }
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
