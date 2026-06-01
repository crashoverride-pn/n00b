/*
 * @file gc.c
 * @brief Copying/compacting garbage collector for n00b arenas.
 *
 * Ported from the original gc.nc.  The algorithm is unchanged: when
 * an arena is full, we create a "to-space", trace roots
 * (user-registered roots, runtime argv/envp, thread stacks), copy
 * live allocations, rewrite pointers, and swap segments.
 */

#define N00B_MEM_INTERNAL_API
#define N00B_USE_INTERNAL_API

#include <string.h>
#include <assert.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "n00b.h"
#include "util/assert.h"
#include "core/gc.h"
#include "core/gc_stack.h"
#include "core/stw.h"
#include "core/alloc_mdata.h"
#include "core/alloc.h"
#include "core/memory_info.h"
#include "core/arena.h"
#include "core/atomic.h"
#include "core/thread.h"
#include "core/lock_common.h"
#include "core/align.h"
#include "core/mmaps.h"
#include "core/runtime.h"
#include "core/pool.h"
#include "core/rt_access.h"
#include "adt/option.h"
#include "adt/dict_untyped.h"

// ============================================================================
// Forward declarations
// ============================================================================

static void n00b_collect_setup(n00b_collect_t *, n00b_arena_t *);
static void n00b_scan_memory_range(n00b_collect_t *, void *, size_t);
static void n00b_process_worklist(n00b_collect_t *);
static bool
n00b_visit_possible_pointer(n00b_collect_t *ctx, uint64_t **base, size_t i, bool base_checked);
static void n00b_collection_cleanup(n00b_collect_t *);
static void n00b_process_finalizers(n00b_collect_t *);
static void n00b_scan_metadata_pools(n00b_collect_t *);
static void n00b_sweep_metadata_pool_leaks(n00b_collect_t *);
static void n00b_scan_thread_stacks(n00b_collect_t *);
static void n00b_scan_thread_lock_chains(n00b_collect_t *ctx, n00b_thread_record_t *rec);
static void n00b_scan_runtime(n00b_collect_t *);
static void n00b_scan_roots(n00b_collect_t *);
static void n00b_add_alloc_to_worklist(n00b_alloc_info_t ainfo, n00b_collect_t *ctx);
static void n00b_add_range_strided_to_worklist(void           *start,
                                               uint64_t        nwords,
                                               uint64_t        stride,
                                               uint64_t        offset,
                                               n00b_collect_t *ctx);
static void n00b_add_range_to_worklist(void *start, uint64_t nwords, n00b_collect_t *ctx);
static bool n00b_add_alloc_range_to_worklist(n00b_collect_t *ctx, n00b_alloc_range_t *range);

// ============================================================================
// Exact stack-map frame publication
// ============================================================================

n00b_gc_stack_policy_t
n00b_gc_stack_get_policy(void)
{
    return (n00b_gc_stack_policy_t)n00b_thread_self()->gc_stack_policy;
}

n00b_gc_stack_policy_t
n00b_gc_stack_set_policy(n00b_gc_stack_policy_t policy)
{
    assert(policy <= N00B_GC_STACK_EXACT_ONLY);

    n00b_thread_t         *thread = n00b_thread_self();
    n00b_gc_stack_policy_t old    = (n00b_gc_stack_policy_t)thread->gc_stack_policy;

    thread->gc_stack_policy = (uint32_t)policy;
    return old;
}

void
n00b_gc_stack_push(n00b_gc_stack_frame_t *frame, const n00b_gc_stack_map_t *map, void **roots)
{
    assert(frame);
    assert(map);
    assert(!map->num_roots || roots);

    n00b_thread_t *thread = n00b_thread_self();

    // During a worker thread's pre-registration init window (after it
    // starts but before n00b_thread_init publishes its stack bounds, so
    // n00b_thread_self() cannot yet resolve it — D-004/D-014/D-019), the
    // thread is not yet a GC participant and has no per-thread frame chain
    // to maintain.  The codegen still emits a frame push in those early
    // prologues; with no owning n00b_thread_t there is nowhere to thread
    // it, so initialize the frame's links to empty and skip publishing.
    // The frame's roots remain live C-stack locals (conservatively
    // scannable) until the thread registers; this restores the
    // always-resolvable invariant the former thread_local self provided.
    if (thread == nullptr) {
        *frame = (n00b_gc_stack_frame_t){
            .prev  = nullptr,
            .map   = map,
            .roots = roots,
        };
        return;
    }

    *frame = (n00b_gc_stack_frame_t){
        .prev  = thread->gc_stack_top,
        .map   = map,
        .roots = roots,
    };
    thread->gc_stack_top = frame;
}

void
n00b_gc_stack_pop(n00b_gc_stack_frame_t *frame)
{
    assert(frame);

    n00b_thread_t *thread = n00b_thread_self();

    // Pre-registration worker window (see n00b_gc_stack_push): the matching
    // push did not publish this frame into any thread's chain, so there is
    // nothing to unlink — just clear the frame.
    if (thread == nullptr) {
        frame->prev  = nullptr;
        frame->map   = nullptr;
        frame->roots = nullptr;
        return;
    }

    assert(thread->gc_stack_top == frame);
    thread->gc_stack_top = frame->prev;
    frame->prev          = nullptr;
    frame->map           = nullptr;
    frame->roots         = nullptr;
}

n00b_jmp_buf_t *
n00b_gc_stack_prepare_jmp(n00b_jmp_buf_t *ctx)
{
    assert(ctx);

    n00b_thread_t *thread = n00b_thread_self();
    assert(thread);

    ctx->n00b_thread       = thread;
    ctx->n00b_gc_stack_top = thread->gc_stack_top;
    return ctx;
}

void
n00b_gc_stack_restore(n00b_gc_stack_frame_t *top)
{
    // Pre-registration worker window (see n00b_gc_stack_push): no owning
    // n00b_thread_t to restore into.  A pre-registration thread has no
    // frame chain, so there is nothing to restore.
    n00b_thread_t *thread = n00b_thread_self();
    if (thread == nullptr) {
        return;
    }
    thread->gc_stack_top = top;
}

[[noreturn]] void
n00b_longjmp(n00b_jmp_buf_t *ctx, int value)
{
    assert(ctx);
    assert(ctx->n00b_thread == n00b_thread_self());

    n00b_gc_stack_restore(ctx->n00b_gc_stack_top);
    longjmp(ctx->n00b_jmp_env, value ? value : 1);
}

// ============================================================================
// Helpers
// ============================================================================

static inline uint32_t
arena_overhead(n00b_arena_t *arena)
{
    return arena->vtable.add_inline_header ? N00B_ALLOC_HDR_SZ : 0;
}

static inline n00b_inline_hdr_t *
alloc_info_raw_hdr(n00b_alloc_info_t info)
{
    assert(n00b_alloc_info_is_heap(info));
    return (info.kind == n00b_alloc_oob) ? (n00b_inline_hdr_t *)info.hdr.oob : info.hdr.in_line;
}

// ============================================================================
// Create destination arena (to-space)
// ============================================================================

static n00b_arena_t *
n00b_create_destination_arena(n00b_arena_t *src)
{
    uint64_t sz = n00b_arena_size(src);

    // If we were really short on memory last time, go up a power of two.
    if (src->current_segment->next_segment || src->alloc_count < N00B_TOO_FEW_ALLOCS) {
        sz *= 2;
    }

    // To-space never gets its own metadata pool; we reuse from-space's.
    // clang-format off
    n00b_arena_t *result = n00b_new_arena(
        .size           = sz,
        .use_gc         = true,
        .no_map         = true,
        .hidden         = true,
        .inline_headers = src->vtable.add_inline_header,
        .name           = "to-space");
    // clang-format on

    assert(result->current_segment->size > 0 && result->current_segment->size >= sz);

    return result;
}

// ============================================================================
// Forward allocation helpers
// ============================================================================

static __attribute__((noinline)) n00b_inline_hdr_t *
n00b_forward_mdata(n00b_collect_t *ctx, n00b_oob_hdr_t *old_map, n00b_inline_hdr_t *new_alloc)
{
    n00b_oob_hdr_t *map_item;

    char   *old_user_ptr = old_map->user_ptr;
    int64_t copy_len     = old_map->alloc_len - arena_overhead(ctx->to_space);
    char   *new_user_ptr = ((char *)new_alloc) + arena_overhead(ctx->to_space);

    assert(new_user_ptr + old_map->alloc_len < ctx->to_space->segment_end);

    // Allocate new OOB record from the shared metadata pool.
    map_item = n00b_alloc_with_opts(
        n00b_oob_hdr_t,
        &(n00b_alloc_opts_t){.allocator = ctx->from_space->vtable.metadata_pool});

    memcpy(map_item, old_map, sizeof(n00b_oob_hdr_t));

    map_item->user_ptr  = new_user_ptr;
    map_item->hcur      = new_alloc;
    map_item->file_name = old_map->file_name;

    if (ctx->to_space->vtable.add_inline_header) {
        memcpy(new_alloc, old_map, sizeof(n00b_inline_hdr_t));
        new_alloc->guard = n00b_gc_guard;
    }

    // Add to the new metadata dict (stored on to-space during collection).
    n00b_dict_untyped_put(ctx->to_space->vtable.metadata, new_user_ptr, map_item);

    memcpy(new_user_ptr, old_user_ptr, copy_len);

    old_map->hcur->moved = true;
    old_map->moved       = true;

    return (n00b_inline_hdr_t *)map_item;
}

// Must have full size headers in this case.
static __attribute__((noinline)) n00b_inline_hdr_t *
n00b_forward_inline(n00b_collect_t    *ctx,
                    n00b_inline_hdr_t *old_alloc,
                    n00b_inline_hdr_t *new_alloc)
{
    assert(!ctx->to_space->vtable.metadata);
    memcpy(new_alloc, old_alloc, old_alloc->alloc_len);

    old_alloc->moved = true;

    return new_alloc;
}

// This needs to act like we actually called n00b_core_alloc().
// But we have solo use of the allocator with no thread contention,
// so we bypass most of it.
//
// Note that we prefer working with the metadata record.  However, we
// will also update the inline alloc record if it's used.
//
// The inline alloc record must be used if the arena collects, yet
// doesn't keep metadata records. Otherwise, we assume that the first
// bytes are the inline header, unless:
//
//  1. The arena 'overhead' is less than sizeof(n00b_inline_hdr_t); or
//  2. The no_inline_headers flag is on (currently unused otherwise).
//
// The default arena keeps inline headers on, so that we can marshal
// out of it.

static inline n00b_inline_hdr_t *
n00b_forward_alloc(n00b_collect_t *ctx, n00b_inline_hdr_t *old)
{
    char *top;
    n00b_inline_hdr_t *new;

    top = n00b_atomic_load(&ctx->to_space->next_alloc);
    new = (n00b_inline_hdr_t *)top;
    top = top + old->alloc_len;

    ctx->to_space->alloc_count++;

    n00b_atomic_store(&ctx->to_space->next_alloc, top);

    n00b_inline_hdr_t    *result;
    void                 *scan_start;
    [[maybe_unused]] bool no_scan;
    uint32_t              nwords;
    n00b_gc_scan_kind_t   scan_kind;

    if (ctx->from_space->vtable.metadata_pool) {
        n00b_option_t(n00b_oob_hdr_t *) old_oob_opt = n00b_to_mem_metadata_record(old);
        n00b_require(n00b_option_is_set(old_oob_opt),
                     "metadata_pool branch implies OOB allocation");
        n00b_oob_hdr_t *old_oob = n00b_option_get(old_oob_opt);
        result                  = n00b_forward_mdata(ctx, old_oob, new);
        scan_start              = ((n00b_oob_hdr_t *)result)->user_ptr;
        no_scan                 = old_oob->no_scan;
        scan_kind               = (n00b_gc_scan_kind_t)old_oob->scan_kind;
        if (old_oob->ptr_words_known) {
            nwords = old_oob->ptr_words;
        }
        else {
            nwords = (old_oob->alloc_len - arena_overhead(ctx->from_space)) / sizeof(void *);
        }
    }
    else {
        result     = n00b_forward_inline(ctx, old, new);
        scan_start = (char *)new + arena_overhead(ctx->to_space);
        no_scan    = new->no_scan;
        scan_kind  = (n00b_gc_scan_kind_t) new->scan_kind;
        if (new->ptr_words_known) {
            nwords = new->ptr_words;
        }
        else {
            nwords = (old->alloc_len - arena_overhead(ctx->from_space)) / sizeof(void *);
        }
    }

#if defined(N00B_DISABLE_NOSCAN)
    bool do_scan = true;
#else
    bool do_scan = !no_scan;
#endif

    if (do_scan) {
        if (scan_kind == N00B_GC_SCAN_KIND_EVERY_OTHER) {
            n00b_add_range_strided_to_worklist(scan_start, nwords, 2, 0, ctx);
        }
        else if (scan_kind == N00B_GC_SCAN_KIND_CALLBACK) {
            n00b_gc_scan_cb_t cb;
            void             *user;
            if (ctx->from_space->vtable.metadata_pool) {
                n00b_option_t(n00b_oob_hdr_t *) old_oob_opt = n00b_to_mem_metadata_record(old);
                n00b_require(n00b_option_is_set(old_oob_opt),
                             "metadata_pool branch implies OOB allocation");
                n00b_oob_hdr_t *old_oob = n00b_option_get(old_oob_opt);
                cb                      = old_oob->scan_cb;
                user                    = old_oob->scan_user;
            }
            else {
                cb   = new->scan_cb;
                user = new->scan_user;
            }
            if (cb) {
                n00b_allocator_t *wpool    = (n00b_allocator_t *)&ctx->work_pool;
                uint64_t          bm_words = n00b_gc_map_word_count(nwords);
                uint64_t         *bitmap
                    = n00b_alloc_array_with_opts(uint64_t,
                                                 bm_words,
                                                 &(n00b_alloc_opts_t){.allocator = wpool});
                for (uint64_t bi = 0; bi < bm_words; bi++)
                    bitmap[bi] = 0;
                n00b_gc_map_t m
                    = {.user_ptr = scan_start, .num_words = nwords, .bitmap = bitmap};
                cb(&m, user);
                for (uint64_t bi = 0; bi < nwords; bi++) {
                    if (n00b_gc_map_is_set(&m, bi)) {
                        n00b_add_range_strided_to_worklist((char *)scan_start
                                                               + bi * sizeof(void *),
                                                           1,
                                                           0,
                                                           0,
                                                           ctx);
                    }
                }
            }
        }
        else {
            n00b_add_range_to_worklist(scan_start, nwords, ctx);
        }
    }

    return result;
}

// ============================================================================
// Pointer translation
// ============================================================================

// Compute the user-data base address from a raw header, using the
// arena configuration (has_oob) rather than bit-testing.
static inline char *
n00b_user_data_base(n00b_inline_hdr_t *hdr, bool has_oob)
{
    if (has_oob) {
        return ((n00b_oob_hdr_t *)hdr)->user_ptr;
    }
    return ((char *)hdr) + sizeof(n00b_inline_hdr_t);
}

static void *
n00b_translate_pointer(n00b_collect_t    *ctx,
                       n00b_inline_hdr_t *old_alloc,
                       uint64_t         **arr,
                       n00b_inline_hdr_t *fw_loc,
                       uint32_t           ix)
{
    uint64_t *old_ptr = n00b_atomic_load((_Atomic(uint64_t *) *)(arr + ix));
    bool      has_oob = ctx->from_space->vtable.metadata_pool != nullptr;

    if (!old_ptr) {
        return nullptr;
    }

    assert(fw_loc);
    assert(fw_loc != old_alloc);

    char *old_base = n00b_user_data_base(old_alloc, has_oob);
    char *new_base = n00b_user_data_base(fw_loc, has_oob);

    ptrdiff_t offset   = (char *)old_ptr - old_base;
    ptrdiff_t user_len = old_alloc->alloc_len - arena_overhead(ctx->from_space);

    if (offset < 0) {
        return nullptr;
    }
    if (offset > user_len) {
        return nullptr;
    }

    return (void *)(new_base + offset);
}

// ============================================================================
// Memo operations
// ============================================================================

static inline bool
n00b_is_first_visit(n00b_collect_t *ctx, n00b_inline_hdr_t *h, n00b_inline_hdr_t **fw)
{
    bool result;

    *fw = n00b_dict_untyped_get(&ctx->memos, h, &result);

    if (!result) {
        assert(!h->moved);
    }

    return !result;
}

static inline void
n00b_register_visit(n00b_collect_t *ctx, n00b_inline_hdr_t *h, n00b_inline_hdr_t *fw)
{
    n00b_dict_untyped_add(&ctx->memos, h, fw);
}

// ============================================================================
// Worklist operations
// ============================================================================

static void
n00b_add_range_to_worklist(void *start, uint64_t nwords, n00b_collect_t *ctx)
{
    n00b_gc_wl_item_t *entry;
    entry = n00b_alloc_with_opts(
        n00b_gc_wl_item_t,
        &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)&ctx->work_pool});
    entry->start     = start;
    entry->num_words = nwords;
    entry->stride    = 0; // 0 == legacy scan-every-word
    entry->offset    = 0;
    n00b_list_push(ctx->worklist, entry);
}

static void
n00b_add_scan_range_to_worklist(n00b_collect_t     *ctx,
                                void               *start,
                                uint64_t            nwords,
                                n00b_gc_scan_kind_t scan_kind,
                                n00b_gc_scan_cb_t   scan_cb,
                                void               *scan_user)
{
    if (!nwords || scan_kind == N00B_GC_SCAN_KIND_NONE) {
        return;
    }

    if (scan_kind == N00B_GC_SCAN_KIND_EVERY_OTHER) {
        n00b_add_range_strided_to_worklist(start, nwords, 2, 0, ctx);
        return;
    }

    if (scan_kind == N00B_GC_SCAN_KIND_CALLBACK && scan_cb) {
        n00b_allocator_t *wpool    = (n00b_allocator_t *)&ctx->work_pool;
        uint64_t          bm_words = n00b_gc_map_word_count(nwords);
        uint64_t         *bitmap   = n00b_alloc_array_with_opts(uint64_t,
                                                      bm_words,
                                                      &(n00b_alloc_opts_t){.allocator = wpool});

        for (uint64_t bi = 0; bi < bm_words; bi++) {
            bitmap[bi] = 0;
        }

        n00b_gc_map_t m = {.user_ptr = start, .num_words = nwords, .bitmap = bitmap};
        scan_cb(&m, scan_user);

        for (uint64_t bi = 0; bi < nwords; bi++) {
            if (n00b_gc_map_is_set(&m, bi)) {
                n00b_add_range_strided_to_worklist((char *)start + bi * sizeof(void *),
                                                   1,
                                                   0,
                                                   0,
                                                   ctx);
            }
        }
        return;
    }

    n00b_add_range_to_worklist(start, nwords, ctx);
}

static bool
n00b_add_alloc_range_to_worklist(n00b_collect_t *ctx, n00b_alloc_range_t *range)
{
    bool found = false;

    n00b_dict_untyped_get(&ctx->memos, range, &found);
    if (found) {
        return false;
    }

    n00b_dict_untyped_add(&ctx->memos, range, range);
    n00b_add_scan_range_to_worklist(ctx,
                                    range->start,
                                    range->len / sizeof(void *),
                                    range->scan_kind,
                                    range->scan_cb,
                                    range->scan_user);
    return true;
}

static void
n00b_add_range_strided_to_worklist(void           *start,
                                   uint64_t        nwords,
                                   uint64_t        stride,
                                   uint64_t        offset,
                                   n00b_collect_t *ctx)
{
    n00b_gc_wl_item_t *entry;
    entry = n00b_alloc_with_opts(
        n00b_gc_wl_item_t,
        &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)&ctx->work_pool});
    entry->start     = start;
    entry->num_words = nwords;
    entry->stride    = stride;
    entry->offset    = offset;
    n00b_list_push(ctx->worklist, entry);
}

static void
n00b_add_alloc_to_worklist(n00b_alloc_info_t ainfo, n00b_collect_t *ctx)
{
    void               *start;
    uint32_t            n;
    n00b_gc_scan_kind_t kind;

    assert(n00b_alloc_info_is_heap(ainfo));

    if (ainfo.kind == n00b_alloc_oob) {
        n00b_oob_hdr_t *oob = ainfo.hdr.oob;
        /* Skip mid-allocation / freed-but-dict-stale OOBs. */
        if (oob->alive == 0) {
            return;
        }
#if !defined(N00B_DISABLE_PTR_WORDS)
        if (oob->ptr_words_known) {
            n = oob->ptr_words;
        }
        else
#endif
        {
            /* OOB records live on metadata-bearing pools (per the
             * @c external_metadata=true path in @c n00b_allocator_setup);
             * those pools do not add an inline header to user
             * allocations, so @c alloc_len here is the bare user-request
             * byte count.  Subtracting @c arena_overhead would underflow
             * for any allocation smaller than @c sizeof(n00b_inline_hdr_t)
             * and yield @c n ~ 0x1FFFFFFC words, walking the scan into
             * dyld shared-cache __DATA and SIGBUSing under macOS COW
             * pressure.  Mirror the bare-divide used in
             * @ref n00b_scan_one_alive_alloc_oob (gc.c, pool-walk-as-roots
             * path) which already noted the same constraint in its
             * comment. */
            n = (uint32_t)((uint64_t)oob->alloc_len / sizeof(void *));
        }
        start = oob->user_ptr;
        kind  = (n00b_gc_scan_kind_t)oob->scan_kind;
    }
    else {
        n00b_inline_hdr_t *hdr = ainfo.hdr.in_line;
#if !defined(N00B_DISABLE_PTR_WORDS)
        if (hdr->ptr_words_known) {
            n = hdr->ptr_words;
        }
        else
#endif
        {
            n = (hdr->alloc_len - arena_overhead(ctx->from_space)) / sizeof(void *);
        }
        start = (char *)hdr + arena_overhead(ctx->from_space);
        kind  = (n00b_gc_scan_kind_t)hdr->scan_kind;
    }

    if (kind == N00B_GC_SCAN_KIND_EVERY_OTHER) {
        n00b_add_range_strided_to_worklist(start, n, 2, 0, ctx);
        return;
    }

    if (kind == N00B_GC_SCAN_KIND_CALLBACK) {
        n00b_gc_scan_cb_t cb;
        void             *user;
        if (ainfo.kind == n00b_alloc_oob) {
            cb   = ainfo.hdr.oob->scan_cb;
            user = ainfo.hdr.oob->scan_user;
        }
        else {
            cb   = ainfo.hdr.in_line->scan_cb;
            user = ainfo.hdr.in_line->scan_user;
        }
        if (cb) {
            n00b_allocator_t *wpool    = (n00b_allocator_t *)&ctx->work_pool;
            uint64_t          bm_words = n00b_gc_map_word_count(n);
            uint64_t         *bitmap
                = n00b_alloc_array_with_opts(uint64_t,
                                             bm_words,
                                             &(n00b_alloc_opts_t){.allocator = wpool});
            for (uint64_t bi = 0; bi < bm_words; bi++)
                bitmap[bi] = 0;
            n00b_gc_map_t m = {.user_ptr = start, .num_words = n, .bitmap = bitmap};
            cb(&m, user);
            /* Visit only marked words.  Add each as its own length-1
             * worklist entry to reuse the existing scan infrastructure. */
            for (uint64_t bi = 0; bi < n; bi++) {
                if (n00b_gc_map_is_set(&m, bi)) {
                    n00b_add_range_strided_to_worklist((char *)start + bi * sizeof(void *),
                                                       1,
                                                       0,
                                                       0,
                                                       ctx);
                }
            }
            return;
        }
    }

    /* ALL / DEFAULT fall through to a plain scan over every word. */
    n00b_add_range_to_worklist(start, n, ctx);
}

static void
n00b_process_worklist(n00b_collect_t *ctx)
{
    n00b_gc_wl_item_t *item;

    while (n00b_list_len(ctx->worklist) > 0) {
        item = n00b_option_get(n00b_list_pop_front(n00b_gc_wl_item_t *, ctx->worklist));
        if (item->stride == 0) {
            n00b_scan_memory_range(ctx, item->start, item->num_words);
        }
        else {
            /* Strided scan: visit slots at indices offset, offset+stride,
             * offset+2*stride, ... while in [0, num_words). */
            uint64_t **base = (uint64_t **)item->start;
            for (uint64_t i = item->offset; i < item->num_words; i += item->stride) {
                n00b_visit_possible_pointer(ctx, base, i, false);
            }
        }
        n00b_free(item);
    }
}

// ============================================================================
// Pointer visitor
// ============================================================================

// This examines a memory cell, rewriting it, if it contains a
// from-space pointer.
//
// If the memory cell contains a pointer into any managed heap space
// at all, we queue a scan for that pointer's allocation, UNLESS
// one of the following things is true:
//
// 1. We have already queued a scan (n00b_is_first_visit will be false)
// 2. `no_scan` is set on the alloc.
//
// For in-heap first visits, n00b_forward_alloc() will always copy,
// and only check the alloc's `no_scan` field.

static inline bool
n00b_visit_possible_pointer(n00b_collect_t *ctx, uint64_t **base, size_t i, bool base_checked)
{
    // Returns 'true' if we find a pointer, so that custom marking functions
    // can more easily be data-dependent.

    if (!base_checked) {
        auto mmap_opt = n00b_mmap_by_address(base);

        if (!n00b_option_is_set(mmap_opt)) {
            // The memory is hidden from us, so we should not try to
            // access it.
            return false;
        }
    }

    n00b_inline_hdr_t *fw_hdr;
    n00b_inline_hdr_t *old_hdr;
    uint64_t          *word = base[i];

    auto mmap_opt = n00b_mmap_by_address((void *)word);

    if (!n00b_option_is_set(mmap_opt)) {
        return false;
    }

    n00b_mmap_info_t *mmap = n00b_option_get(mmap_opt);

    if (!n00b_mmap_is_gc_scannable(mmap)) {
        return false;
    }

    switch (mmap->kind) {
    case n00b_mmap_managed_segment:
    case n00b_mmap_sys_segment:
    case n00b_mmap_pool:
    case n00b_mmap_internal:
        break;
    case n00b_mmap_stack:
        return false; // We will scan this separately.
    case n00b_mmap_static:
        /* A candidate pointer whose VALUE lands inside a dyld
         * library segment (our binary + every system dylib) cannot
         * reach any of our heap roots — those libraries don't hold
         * pointers back into our managed arenas.  Worse, the
         * subsequent @ref n00b_find_alloc_info deref below would
         * read the candidate's bytes as an alloc header.  Under
         * macOS burst load the kernel compresses out shared-cache
         * pages that the perms probe just brought in; that deref
         * then SIGBUSes (verified by crash report: fault inside
         * visit_possible_pointer with si_addr in libobjc.A.dylib's
         * __OBJC_RO / libc++.1.dylib's __TEXT).  Our own binary's
         * TU-scope globals are scanned via @c rt->gc_roots, so we
         * lose nothing by skipping the candidate-into-static
         * follow. */
        return false;
    case n00b_mmap_zero_page:
    case n00b_mmap_api_mmap:
    case n00b_mmap_arena:
        return false;
    default:
        // This means we have a pointer into internal memory, in GC'd
        // space, which we should be avoiding.
        //
        // Or, there could be corruption, etc.
        abort();
    }

    auto ainfo = n00b_find_alloc_info(word);

    if (n00b_alloc_info_is_static_range(ainfo)) {
        n00b_add_alloc_range_to_worklist(ctx, ainfo.hdr.range);
        return false;
    }

    if (!n00b_alloc_info_is_heap(ainfo)) {
        if (mmap->kind == n00b_mmap_static) {
            return false;
        }

        ainfo = n00b_find_alloc_info(word, .scan_for_header = true);

        if (n00b_alloc_info_is_static_range(ainfo)) {
            n00b_add_alloc_range_to_worklist(ctx, ainfo.hdr.range);
            return false;
        }

        if (!n00b_alloc_info_is_heap(ainfo)) {
            auto range_opt = n00b_mmap_range_by_address((void *)word);

            if (n00b_option_is_set(range_opt)) {
                n00b_add_alloc_range_to_worklist(ctx, n00b_option_get(range_opt));
            }

            return false;
        }
    }

    old_hdr = alloc_info_raw_hdr(ainfo);

    /* Stamp the GC epoch onto the OOB record so the post-mark
     * sweep can tell "reached this round" from "stale, leak". Done
     * every visit, not just first — cheap and idempotent. */
    if (ainfo.kind == n00b_alloc_oob) {
        ainfo.hdr.oob->gc_epoch = ctx->current_epoch;
    }

    bool in_from_space = mmap->allocator == (n00b_allocator_t *)ctx->from_space;

    if (n00b_is_first_visit(ctx, old_hdr, &fw_hdr)) {
        if (in_from_space) {
            fw_hdr = n00b_forward_alloc(ctx, old_hdr);
            assert(fw_hdr);
        }
        else {
            fw_hdr = nullptr;
#if !defined(N00B_DISABLE_NOSCAN)
            bool no_scan = (ainfo.kind == n00b_alloc_oob) ? ainfo.hdr.oob->no_scan
                                                          : ainfo.hdr.in_line->no_scan;
            if (!no_scan)
#endif
            {
                n00b_add_alloc_to_worklist(ainfo, ctx);
            }
        }
        // This has to happen after we create the fw_hdr object if
        // it's in the heap we're collecting.
        n00b_register_visit(ctx, old_hdr, fw_hdr);
    }
    else {
        if (in_from_space) {
            assert(fw_hdr);
        }
    }

    if (in_from_space) {
        uint64_t *v = n00b_translate_pointer(ctx, old_hdr, base, fw_hdr, i);

        if (v) {
            base[i] = v;
            return true;
        }
    }

    return false;
}

// ============================================================================
// Memory range scanning
// ============================================================================

static void
n00b_scan_memory_range(n00b_collect_t *ctx, void *start, size_t nwords)
{
    size_t     i               = nwords;
    uint64_t **base            = (uint64_t **)start;
    // Cache page readability to avoid per-word permission probes.
    size_t     page_size       = n00b_page_size;
    uintptr_t  page_mask       = ~(uintptr_t)(page_size - 1);
    uintptr_t  last_page       = 0;
    bool       last_page_ok    = false;
    bool       last_page_valid = false;

    while (i--) {
        void     *slot = (void *)(base + i);
        uintptr_t page = ((uintptr_t)slot) & page_mask;

        if (!last_page_valid || page != last_page) {
            auto slot_mmap_opt = n00b_mmap_by_address(slot);

            if (n00b_option_is_set(slot_mmap_opt)) {
                n00b_mmap_info_t *slot_mmap = n00b_option_get(slot_mmap_opt);

                if (slot_mmap->kind == n00b_mmap_stack) {
                    n00b_mmap_perms_t perms = n00b_check_memory_perms(slot);
                    last_page_ok            = perms != n00b_mmap_perms_no_access;
                }
                else {
                    /* Trust the registry for non-stack kinds. Static
                     * pages from our binary (where g_endpoint and
                     * other ncc-registered roots live) MUST be
                     * scannable — otherwise scan_roots can never
                     * forward pointer fields like @c events.data when
                     * the GC moves the backing array, and downstream
                     * code derefs an unmapped pointer. Dyld __DATA
                     * pages that may COW-fault to SIGBUS are handled
                     * defensively in @ref n00b_visit_possible_pointer
                     * via the @c case n00b_mmap_static @c return false
                     * (the candidate-follow path), not by refusing the
                     * slot read here. */
                    last_page_ok = true;
                }
            }
            else {
                n00b_mmap_perms_t perms = n00b_check_memory_perms(slot);
                last_page_ok            = perms != n00b_mmap_perms_no_access;
            }

            last_page       = page;
            last_page_valid = true;
        }

        if (!last_page_ok) {
            continue;
        }

        n00b_visit_possible_pointer(ctx, base, i, true);
    }
}

// ============================================================================
// Thread lock-chain scanning
// ============================================================================

static inline size_t
n00b_words_for_scan(size_t bytes)
{
    return (bytes + sizeof(void *) - 1) / sizeof(void *);
}

static void
n00b_scan_thread_lock_chains(n00b_collect_t *ctx, n00b_thread_record_t *rec)
{
    /* Locks can live in hidden, non-moving pools.  Thread-record scanning
     * updates the chain head, but hidden lock storage is not discoverable
     * through the mmap registry, so scan only the active chains here instead
     * of registering every initialized lock as a durable root. */
    n00b_lock_base_t *lock = n00b_atomic_load(&rec->exclusive_locks);

    while (lock != nullptr) {
        n00b_scan_memory_range(ctx, lock, n00b_words_for_scan(sizeof(n00b_lock_base_t)));
        n00b_process_worklist(ctx);
        lock = n00b_atomic_load(&lock->next_thread_lock);
    }

    n00b_thread_read_log_t *rlog = n00b_atomic_load(&rec->read_locks);

    while (rlog != nullptr) {
        n00b_scan_memory_range(ctx, rlog, n00b_words_for_scan(sizeof(n00b_thread_read_log_t)));
        n00b_process_worklist(ctx);

        n00b_lock_base_t *read_lock = (n00b_lock_base_t *)rlog->obj;
        if (read_lock != nullptr) {
            n00b_scan_memory_range(ctx,
                                   read_lock,
                                   n00b_words_for_scan(sizeof(n00b_lock_base_t)));
            n00b_process_worklist(ctx);
        }

        rlog = rlog->next_entry;
    }
}

// ============================================================================
// Thread stack scanning
// ============================================================================

static __attribute__((noinline)) void
n00b_scan_thread_stacks(n00b_collect_t *ctx)
{
    volatile n00b_thread_t *t;
    n00b_runtime_t         *rt = n00b_get_runtime();

    for (volatile uint32_t i = 0; i < rt->max_threads; i++) {
        t = n00b_atomic_load(&rt->threads[i].thread);

        if (!t) {
            continue;
        }

        n00b_gc_stack_policy_t stack_policy        = (n00b_gc_stack_policy_t)t->gc_stack_policy;
        bool                   exact_stack_scanned = false;

        if (stack_policy != N00B_GC_STACK_CONSERVATIVE) {
            n00b_gc_stack_frame_t *frame = (n00b_gc_stack_frame_t *)t->gc_stack_top;

            if (frame) {
                exact_stack_scanned = true;
            }

            while (frame) {
                const n00b_gc_stack_map_t *map = frame->map;

                assert(map);
                assert(map->num_slots == 0 || map->slots);
                assert(map->num_roots == 0 || frame->roots);

                for (uint32_t si = 0; si < map->num_slots; si++) {
                    const n00b_gc_stack_slot_t *slot = &map->slots[si];

                    assert(slot->root_index < map->num_roots);

                    if (!slot->num_words) {
                        continue;
                    }

                    void *addr = frame->roots[slot->root_index];
                    if (addr) {
                        n00b_scan_memory_range(ctx, addr, slot->num_words);
                    }
                }

                frame = frame->prev;
            }
        }

        if (stack_policy == N00B_GC_STACK_EXACT_ONLY
            || (stack_policy == N00B_GC_STACK_EXACT_WITH_FALLBACK && exact_stack_scanned)) {
            goto scan_thread_state;
        }

        // ISOLATION (WP-002 Phase 5, D-025 Q1).  An isolated worker is
        // EXCLUDED from the conservative C-stack range scan below: it has
        // declared (by setting `.isolation` on n00b_thread_spawn) that the
        // GC must NOT treat its raw C stack as a root source — the worker
        // self-registers (via n00b_gc_register_root / an explicit GC stack
        // map) any heap memory it wants kept alive.  This is a NARROW change
        // to the scan-set INCLUSION TEST only; it does not alter the D-007
        // exact-vs-conservative scan model (above) or the shadow-stack
        // push/pop.  The thread struct, its n00b_thread_record_t, and its
        // lock chains are STILL scanned (the `scan_thread_state` block below)
        // so the GC's view of the worker's locks is never corrupted — only
        // the conservative range scan over the worker's own C stack is
        // skipped.  SAFETY: excluding the C-stack scan while a worker holds
        // the only reference to a heap object on that stack loses that root
        // → use-after-free under collection; honoring the self-registration
        // contract is the isolated worker's responsibility.
        if (t->gc_isolated) {
            goto scan_thread_state;
        }

        // Since n00b_scan_memory_range cares about aligned words, we will
        // convert the stack bounds to pointers to the type uint64_t; that
        // way we can subtract the pointers.
        //
        // Remember that the stack grows down (on machines we are
        // targeting), so the "top" will be the smaller address, and
        // the one we want to start with in the scan.

        uint64_t *top  = (uint64_t *)t->stack_top;
        uint64_t *base = (uint64_t *)t->stack_map->end;

        // Some basic sanity checking. The stack should always, always be word
        // aligned.

#ifndef _WIN32
        if (((uint64_t)top) < t->stack_map->start) {
            top = (uint64_t *)t->stack_map->start;
        }
#endif

        top  = (uint64_t *)n00b_align_ceil((uint64_t)top, 0x08);
        base = (uint64_t *)n00b_align_floor((uint64_t)base, 0x08);

        assert(base > top);

        uint64_t num_words = base - top;

        assert(num_words > 0);

        n00b_scan_memory_range(ctx, top, num_words);

scan_thread_state:
        // Scan the thread structure while we're here.
        n00b_scan_memory_range(ctx, (void *)t, sizeof(n00b_thread_t) / sizeof(void *));
        // Scan the thread RECORD too — it lives in `rt->threads[i]` and
        // holds pointers into the GC heap that nothing else scans:
        // `exclusive_locks` / `read_locks` (heads of per-thread lock
        // accounting chains, where each in-heap `n00b_mutex_t` /
        // `n00b_rwlock_t` lives inside a relocatable allocation — e.g.
        // an embedded field of a GC-allocated `Regex`), `lock_wait_target`,
        // and `regex_last_detail` (per-thread error string).
        //
        // Without this scan, after a collection that relocates a heap
        // lock, the chain head still points at the old (freed) address,
        // and the next `n00b_lock_acquire_accounting` walks one step
        // into freed memory.  Reproducible by running `regex_count_all`
        // in a tight loop over a multi-hundred-KB haystack — the SIMD
        // match path generates enough GC pressure to force a collection
        // mid-lock, after ~1000 iterations.
        n00b_scan_memory_range(ctx,
                               (void *)&rt->threads[i],
                               n00b_words_for_scan(sizeof(n00b_thread_record_t)));
        n00b_scan_thread_lock_chains(ctx, &rt->threads[i]);
    }
}

// ============================================================================
// Runtime scanning (argv / envp)
// ============================================================================

static void
n00b_scan_runtime(n00b_collect_t *ctx)
{
    n00b_runtime_t *rt = n00b_get_runtime();

    // Scan argv array (array of char *)
    if (rt->argv.data && rt->argv.len) {
        n00b_scan_memory_range(ctx,
                               rt->argv.data,
                               rt->argv.len * sizeof(char *) / sizeof(void *));
        n00b_process_worklist(ctx);
    }

    // Scan envp array (array of char *)
    if (rt->envp.data && rt->envp.len) {
        n00b_scan_memory_range(ctx,
                               rt->envp.data,
                               rt->envp.len * sizeof(char *) / sizeof(void *));
        n00b_process_worklist(ctx);
    }
}

// ============================================================================
// User-registered root scanning
// ============================================================================

static void
n00b_scan_roots(n00b_collect_t *ctx)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    size_t          n  = rt->gc_roots.len;

    for (size_t i = 0; i < n; i++) {
        n00b_gc_root_t *root = &rt->gc_roots.data[i];
        n00b_scan_memory_range(ctx, root->addr, root->num_words);
        n00b_process_worklist(ctx);
    }
}

// ============================================================================
// Root registration API
// ============================================================================
//
// Defer queue for pre-init callers (WP-003 / D-036, fix F-4).
//
// ncc's `--ncc-auto-gc-roots` transform emits a
// `[[gnu::constructor]]` function in every libn00b TU that has
// TU-scope pointer-bearing decls. Those constructors run during
// dynamic loader init — BEFORE `n00b_init()` builds the runtime and
// allocates `runtime->gc_roots`. Calling the lock-free runtime-
// resident path (`_n00b_gc_register_root` / the public
// `n00b_gc_register_roots` chain) from that context would deref a
// null `n00b_get_runtime()` and assert.
//
// Disposition (D-036): when no runtime exists yet, batch-API calls
// park their entries in a TU-local linked list of chunks.
// `n00b_init` flushes the queue after the runtime is set up and
// `runtime->gc_roots` exists, then frees the chunks.
//
// Allocator choice: the queue MUST work before the n00b allocator is
// available, so chunk allocation uses libc `calloc` directly. This
// is the same approach used by `src/net/quic/rpc.c`'s
// `defer_register` (deferred RPC registrations), and it is the only
// option for a defer queue that exists by definition before any n00b
// pool/allocator. The `__ncc_` prefix on the static head pointer
// ensures the auto-roots transform itself does not try to register
// the queue head as a root (spec § 2.2 row 3).
//
// Concurrency: dynamic loader `[[gnu::constructor]]` chains run
// sequentially on a single thread before `main()`, so writes to the
// queue during ctor phase are inherently single-threaded. The flush
// runs once from `n00b_init` (also single-threaded). After the
// flush, runtime-resident callers go through `_n00b_gc_register_root`
// directly — the queue is empty and untouched. No lock required at
// any point. Matches D-025's lock-free init-time-only discipline.
//
// The single-entry `_n00b_gc_register_root` does NOT need defer
// logic: it is only called from runtime-resident code (libn00b's
// own `n00b_gc_register_root` macro callers, used during normal
// initialization sequenced after `n00b_init`), never from a
// pre-init constructor. The auto-roots transform emits batch-API
// calls exclusively (D-005). Asserting on runtime-presence in the
// single-entry path stays as the existing implicit precondition.

typedef struct __ncc_gc_root_defer_chunk_t {
    struct __ncc_gc_root_defer_chunk_t *next;
    size_t                              count;
    size_t                              capacity;
    n00b_gc_root_t                      entries[];
} __ncc_gc_root_defer_chunk_t;

// `__ncc_` prefix per spec § 2.2 row 3: the auto-roots transform
// must not try to auto-register the queue head pointer as a root.
static __ncc_gc_root_defer_chunk_t *__ncc_gc_root_defer_head = nullptr;

#define N00B_GC_ROOT_DEFER_CHUNK_CAP 64u

static void
defer_register_roots(const n00b_gc_root_t *roots, size_t count)
{
    // Single-threaded during dynamic loader ctor phase; no lock.
    size_t i = 0;
    while (i < count) {
        __ncc_gc_root_defer_chunk_t *head = __ncc_gc_root_defer_head;
        if (!head || head->count == head->capacity) {
            size_t cap   = N00B_GC_ROOT_DEFER_CHUNK_CAP;
            size_t bytes = sizeof(__ncc_gc_root_defer_chunk_t) + cap * sizeof(n00b_gc_root_t);
            __ncc_gc_root_defer_chunk_t *fresh
                = (__ncc_gc_root_defer_chunk_t *)calloc(1, bytes);
            if (!fresh) {
                // Calloc failure during pre-init root registration:
                // the loader cannot proceed. There is no n00b panic
                // primitive yet (the runtime isn't up), so abort
                // here. Matches the policy in
                // `src/net/quic/rpc.c::defer_register` (which
                // silently drops on calloc failure but is non-load-
                // bearing); GC roots are load-bearing, so abort.
                abort();
            }
            fresh->next              = __ncc_gc_root_defer_head;
            fresh->count             = 0;
            fresh->capacity          = cap;
            __ncc_gc_root_defer_head = fresh;
            head                     = fresh;
        }
        size_t take = head->capacity - head->count;
        if (take > count - i) {
            take = count - i;
        }
        for (size_t j = 0; j < take; j++) {
            head->entries[head->count + j] = roots[i + j];
        }
        head->count += take;
        i += take;
    }
}

// True iff the runtime has been built (i.e., `n00b_init` populated
// the `n00b_default_runtime` option). Constructor-time callers see
// `false`; runtime-resident callers see `true`. Mirrors the
// `runtime_ready()` pattern in `src/net/quic/rpc.c`.
static bool
_n00b_gc_runtime_ready(void)
{
    return n00b_option_is_set(n00b_default_runtime);
}

void
_n00b_gc_register_root(void *addr, size_t num_words)
{
    n00b_runtime_t *rt  = n00b_get_runtime();
    size_t          len = n00b_list_len(rt->gc_roots);

    if (addr == nullptr || num_words == 0) {
        return;
    }

    for (size_t i = 0; i < len; i++) {
        n00b_gc_root_t existing = n00b_list_get(rt->gc_roots, i);

        if (existing.addr == addr) {
            if (existing.num_words < num_words) {
                existing.num_words = num_words;
                n00b_list_set(rt->gc_roots, i, existing);
            }
            return;
        }
    }

    n00b_gc_root_t root = {.addr = addr, .num_words = num_words};
    n00b_list_push(rt->gc_roots, root);
}

void
n00b_gc_register_roots(const n00b_gc_root_t *roots, size_t count)
{
    if (roots == nullptr || count == 0) {
        return;
    }

    // Pre-init: park entries in the defer queue. `n00b_init` flushes
    // them via `_n00b_gc_flush_deferred_roots` after the runtime is
    // ready (F-4 / D-036).
    if (!_n00b_gc_runtime_ready()) {
        defer_register_roots(roots, count);
        return;
    }

    // Runtime-resident path: delegate to the single-entry helper so
    // dedup semantics (address match + num_words update) and the
    // lock-free init-time-only discipline live in one place
    // (D-005 / D-025).
    for (size_t i = 0; i < count; i++) {
        _n00b_gc_register_root(roots[i].addr, roots[i].num_words);
    }
}

void
_n00b_gc_flush_deferred_roots(void)
{
    // Called once from `n00b_init` after `runtime->gc_roots` exists
    // and the runtime is publicly visible via `n00b_default_runtime`.
    // Replays parked entries in registration order (chunks form a
    // LIFO; reverse so the earliest registrations land first), then
    // frees each chunk. After this returns the queue is empty for
    // the lifetime of the process — runtime-resident callers go
    // through the direct path in `n00b_gc_register_roots`.
    __ncc_gc_root_defer_chunk_t *head = __ncc_gc_root_defer_head;
    __ncc_gc_root_defer_head          = nullptr;

    // Reverse the list so earlier-registered entries flush first.
    __ncc_gc_root_defer_chunk_t *prev = nullptr;
    while (head) {
        __ncc_gc_root_defer_chunk_t *next = head->next;
        head->next                        = prev;
        prev                              = head;
        head                              = next;
    }

    while (prev) {
        for (size_t i = 0; i < prev->count; i++) {
            _n00b_gc_register_root(prev->entries[i].addr, prev->entries[i].num_words);
        }
        __ncc_gc_root_defer_chunk_t *next = prev->next;
        free(prev);
        prev = next;
    }
}

void
_n00b_gc_unregister_root(void *addr)
{
    n00b_runtime_t *rt  = n00b_get_runtime();
    size_t          len = n00b_list_len(rt->gc_roots);

    for (size_t i = 0; i < len; i++) {
        n00b_gc_root_t root = n00b_list_get(rt->gc_roots, i);

        if (root.addr == addr) {
            (void)n00b_list_delete(rt->gc_roots, i);
            return;
        }
    }
}

// ============================================================================
// Finalizer processing
// ============================================================================

static inline bool
n00b_addr_in_arena(void *addr, n00b_arena_t *arena)
{
    n00b_segment_t *seg = arena->current_segment;

    while (seg) {
        char *start = (char *)&seg->mem[0];
        char *end   = start + (seg->size - sizeof(n00b_segment_t));

        if ((char *)addr >= start && (char *)addr < end) {
            return true;
        }
        seg = seg->next_segment;
    }
    return false;
}

// Check if a finalizer entry's object was in the from_space being collected.
// For OOB arenas, the alloc_info is an OOB record (in the metadata pool,
// NOT in from_space), so we check the OOB record's user_ptr instead.
// For inline-only arenas, the alloc_info IS the inline header in from_space.
static inline bool
n00b_finalizer_in_from_space(n00b_finalizer_info_t *entry, n00b_collect_t *ctx)
{
    if (ctx->from_space->vtable.metadata_pool) {
        // OOB arena: alloc_info is n00b_oob_hdr_t*, check user_ptr.
        n00b_oob_hdr_t *oob = (n00b_oob_hdr_t *)entry->alloc_info;
        return n00b_addr_in_arena(oob->user_ptr, ctx->from_space);
    }
    // Inline-only: alloc_info is the inline header in the segment.
    return n00b_addr_in_arena(entry->alloc_info, ctx->from_space);
}

// ============================================================================
// Metadata-bearing pool walk + leak sweep.
//
// Every pool initialised with external_metadata=true registers in
// rt->metadata_pools at construction. n00b_scan_metadata_pools walks
// each pool's metadata dict, finds buckets whose OOB record carries
// alive=1, stamps the current epoch on the record, and adds the
// alloc to the worklist so its outbound pointers get traced — the
// pool walk thereby substitutes for the older "register pool struct
// as a GC root" workaround.
//
// n00b_sweep_metadata_pool_leaks runs after the worklist has
// drained.  Any alive alloc whose gc_epoch is still stale was not
// reachable from real roots and is by definition a leak: the sweep
// frees it back to the pool. When rt->debug_leak_detect is set,
// each leak is printed with its tinfo + alloc_len + file_name so
// callers using n00b_debug_find_leaks() get a precise origin.
// ============================================================================

static void
n00b_scan_one_alive_alloc_oob(n00b_collect_t *ctx, n00b_oob_hdr_t *oob)
{
    /* Stamp the epoch — the alloc is reachable in this collection
     * by virtue of being an alive pool slot, regardless of whether
     * any real root pointed at it. The post-mark sweep treats
     * "alive && epoch stale" as leak; this prevents the pool walk
     * itself from manufacturing false-positive leaks. */
    oob->gc_epoch = ctx->current_epoch;

    /* For no_scan / SCAN_KIND_NONE allocs we still want the epoch
     * stamp (above) but nothing to follow. */
    n00b_gc_scan_kind_t kind = (n00b_gc_scan_kind_t)oob->scan_kind;
    if (oob->no_scan || kind == N00B_GC_SCAN_KIND_NONE) {
        return;
    }

    void    *start;
    uint32_t n;
    start = oob->user_ptr;
#if !defined(N00B_DISABLE_PTR_WORDS)
    n = oob->ptr_words;
    if (!n)
#endif
    {
        /* Pool allocs are not in any arena, so the arena_overhead
         * subtraction n00b_add_alloc_to_worklist applies doesn't
         * apply here: alloc_len is the bare user request. */
        n = oob->alloc_len / sizeof(void *);
    }

    if (kind == N00B_GC_SCAN_KIND_EVERY_OTHER) {
        n00b_add_range_strided_to_worklist(start, n, 2, 0, ctx);
        return;
    }

    if (kind == N00B_GC_SCAN_KIND_CALLBACK) {
        n00b_add_scan_range_to_worklist(ctx, start, n, kind, oob->scan_cb, oob->scan_user);
        return;
    }

    /* DEFAULT / fallback: conservative scan every word. */
    n00b_add_range_to_worklist(start, n, ctx);
}

static void
n00b_scan_metadata_pools(n00b_collect_t *ctx)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    if (!rt || rt->metadata_pools.data == nullptr) {
        return;
    }

    size_t npools = n00b_list_len(rt->metadata_pools);
    for (size_t pi = 0; pi < npools; pi++) {
        n00b_allocator_t *allocator = n00b_list_get(rt->metadata_pools, pi);
        if (allocator == nullptr || allocator->metadata == nullptr) {
            continue;
        }

        /* Walk the dict store's bucket array directly. We can't use
         * the public get/put API to iterate, but the bucket layout
         * is stable: occupied = key != nullptr && !(flags & DELETED). */
        n00b_dict_untyped_store_t *store = n00b_atomic_load(&allocator->metadata->store);
        if (store == nullptr) {
            continue;
        }
        uint32_t slots = store->last_slot + 1;
        for (uint32_t bi = 0; bi < slots; bi++) {
            n00b_dict_untyped_bucket_t *b = &store->buckets[bi];
            if (b->key == nullptr) {
                continue;
            }
            if (n00b_atomic_load(&b->flags) & N00B_HT_FLAG_DELETED) {
                continue;
            }
            n00b_oob_hdr_t *oob = (n00b_oob_hdr_t *)b->value;
            if (oob == nullptr || !oob->alive) {
                continue;
            }
            n00b_scan_one_alive_alloc_oob(ctx, oob);
        }
    }
}

static void
n00b_sweep_metadata_pool_leaks(n00b_collect_t *ctx)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    if (!rt || rt->metadata_pools.data == nullptr) {
        return;
    }

    bool debug = n00b_atomic_load(&rt->debug_leak_detect);

    size_t npools = n00b_list_len(rt->metadata_pools);
    for (size_t pi = 0; pi < npools; pi++) {
        n00b_allocator_t *allocator = n00b_list_get(rt->metadata_pools, pi);
        if (allocator == nullptr || allocator->metadata == nullptr) {
            continue;
        }

        n00b_dict_untyped_store_t *store = n00b_atomic_load(&allocator->metadata->store);
        if (store == nullptr) {
            continue;
        }
        uint32_t slots = store->last_slot + 1;

        for (uint32_t bi = 0; bi < slots; bi++) {
            n00b_dict_untyped_bucket_t *b = &store->buckets[bi];
            if (b->key == nullptr) {
                continue;
            }
            if (n00b_atomic_load(&b->flags) & N00B_HT_FLAG_DELETED) {
                continue;
            }
            n00b_oob_hdr_t *oob = (n00b_oob_hdr_t *)b->value;
            if (oob == nullptr || !oob->alive) {
                continue;
            }
            if (oob->gc_epoch == ctx->current_epoch) {
                /* Reached by this collection — alive and traced,
                 * not a leak. */
                continue;
            }

            /* Stale-epoch alive alloc — leak. Two policies:
             *
             *   debug=true   → print the callsite. Do NOT reclaim:
             *                  the false-positive case (e.g. live
             *                  state reachable only through a
             *                  non-scannable container) would
             *                  otherwise turn into use-after-free.
             *                  Bumping gc_epoch keeps the same
             *                  alloc from being reported every
             *                  collection.
             *   debug=false  → silent reclaim path, the original
             *                  "auto-return-to-pool" design.
             */
            if (debug) {
                fprintf(stderr,
                        "n00b leak: pool=%s alloc_len=%u tinfo=%llu "
                        "at %s ptr=%p\n",
                        allocator->debug_name ? allocator->debug_name : "?",
                        (unsigned)oob->alloc_len,
                        (unsigned long long)oob->tinfo,
                        oob->file_name ? oob->file_name : "?",
                        oob->user_ptr);
                oob->gc_epoch = ctx->current_epoch;
                continue;
            }

            /* Mark dead, then return to pool. n00b_free runs
             * finalizers + the allocator's free routine — same
             * teardown the caller would have done had they
             * remembered to. */
            void *user_ptr = oob->user_ptr;
            oob->alive     = 0;
            if (user_ptr) {
                n00b_free(user_ptr);
            }
        }
    }
}

static void
n00b_process_finalizers(n00b_collect_t *ctx)
{
    n00b_runtime_t *rt = n00b_get_runtime();

    if (!rt || !rt->finalizers.data) {
        return;
    }

    size_t len = n00b_list_len(rt->finalizers);

    for (size_t i = len; i > 0; i--) {
        n00b_finalizer_info_t *entry = n00b_list_get(rt->finalizers, i - 1);
        bool                   found;
        n00b_inline_hdr_t     *fw;

        // alloc_info is null for entries tied to allocators without
        // GC metadata (e.g. system_pool). Such allocations are never
        // in a from_space, so the sweep has nothing to do — release
        // happens via the n00b_free path instead.
        if (entry->alloc_info == nullptr) {
            continue;
        }

        fw = n00b_dict_untyped_get(&ctx->memos, entry->alloc_info, &found);

        if (found) {
            // Object survived — update alloc_info to the forwarded header.
            // fw is nullptr when the allocation was scanned but lives in
            // a *different* arena (not the one being collected).  In that
            // case, leave alloc_info alone — it still points to the
            // original (valid) header in that other arena.
            if (fw) {
                entry->alloc_info = fw;
            }
            // user_ptr typically points outside the collected arena
            // (e.g., a lock in system_pool), so no update needed.
        }
        else if (n00b_finalizer_in_from_space(entry, ctx)) {
            // Object is dead — run finalizer and remove entry.
            entry->funcptr(entry->user_ptr);
            (void)n00b_list_delete(rt->finalizers, i - 1);
            n00b_free(entry);
        }
        // else: object in a different arena, leave alone.
    }
}

// ============================================================================
// Collection setup
// ============================================================================

static void
n00b_collect_setup(n00b_collect_t *ctx, n00b_arena_t *from_space)
{
    ctx->from_space = from_space;
    ctx->to_space   = n00b_create_destination_arena(from_space);

    /* Bump the runtime's GC epoch counter and snapshot it onto the
     * collection context. The mark phase stamps this value onto
     * every metadata-bearing alloc it reaches (via the OOB record's
     * gc_epoch field). After mark, alloc records still flagged
     * `alive` whose epoch is stale = handed out + not reached =
     * leaks; the metadata-pool sweep returns them to their pool. */
    {
        n00b_runtime_t *rt = n00b_get_runtime();
        if (rt) {
            ctx->current_epoch = n00b_atomic_add(&rt->gc_current_epoch, 1) + 1;
        }
        else {
            ctx->current_epoch = 0;
        }
    }

    // clang-format off
    n00b_pool_init(&ctx->work_pool,
                   .__system = true,
                   .hidden   = true,
                   .name     = "gc_worklist");

    n00b_allocator_t *wa = (n00b_allocator_t *)&ctx->work_pool;

    ctx->worklist = n00b_list_new_cap(n00b_gc_wl_item_t *,
                                      N00B_GC_WL_START_SIZE, wa);

    n00b_dict_untyped_init(&ctx->memos,
                           .start_capacity = N00B_GC_WL_START_SIZE,
                           .allocator      = wa,
                           .hash           = n00b_hash_word,
                           .skip_obj_hash  = true);
    // clang-format on

    // If from-space uses OOB metadata, create a fresh dict in the
    // same metadata pool and attach it to to-space for forwarding.
    if (from_space->vtable.metadata_pool) {
        n00b_allocator_t *md_pool = from_space->vtable.metadata_pool;

        n00b_dict_untyped_t *new_md
            = n00b_alloc_with_opts(n00b_dict_untyped_t,
                                   &(n00b_alloc_opts_t){.allocator = md_pool});
        n00b_dict_untyped_init(new_md,
                               .start_capacity = from_space->alloc_count * 2,
                               .allocator      = md_pool,
                               .hash           = n00b_hash_word,
                               .skip_obj_hash  = true);
        ctx->to_space->vtable.metadata = new_md;
    }

    assert(ctx->to_space->segment_end
           == ((char *)ctx->to_space->current_segment) + ctx->to_space->current_segment->size);
    assert(ctx->to_space && ctx->to_space != ctx->from_space);
}

// ============================================================================
// Collection cleanup — swap segments and destroy temporaries
// ============================================================================

// Free all OOB values in the old metadata dict, then free the dict
// itself.  Both the OOB records and the dict internals live in the
// metadata pool, so n00b_free returns their slots to the free list.
static void
n00b_free_old_metadata(n00b_dict_untyped_t *old_dict)
{
    n00b_dict_untyped_store_t *store = n00b_atomic_load(&old_dict->store);

    if (store) {
        for (uint32_t i = 0; i <= store->last_slot; i++) {
            uint32_t flags = n00b_atomic_load(&store->buckets[i].flags);

            if (store->buckets[i].value && !(flags & N00B_HT_FLAG_DELETED)) {
                n00b_free(store->buckets[i].value);
            }
        }
        n00b_free(store);
    }

    n00b_free(old_dict);
}

static void
n00b_collection_cleanup(n00b_collect_t *ctx)
{
    // Swap the segment linked list so the from-space arena keeps its
    // identity but now holds the live (to-space) data.

    n00b_segment_t *new_segment  = ctx->to_space->current_segment;
    void           *old_segments = (void *)ctx->from_space->current_segment;

    ctx->from_space->current_segment = new_segment;
    ctx->from_space->next_alloc      = ctx->to_space->next_alloc;
    ctx->from_space->segment_end     = ctx->to_space->segment_end;

    // Swap the metadata dict: free old OOB records and install the
    // new dict.  The metadata pool itself is shared and stays put.
    if (ctx->from_space->vtable.metadata_pool) {
        n00b_dict_untyped_t *old_dict    = ctx->from_space->vtable.metadata;
        ctx->from_space->vtable.metadata = ctx->to_space->vtable.metadata;
        ctx->to_space->vtable.metadata   = nullptr;

        if (old_dict) {
            n00b_free_old_metadata(old_dict);
        }
    }

    ctx->to_space->current_segment = old_segments;
    ctx->to_space->vtable.hidden   = false;

    n00b_register_arena_segment(new_segment,
                                ctx->from_space->segment_end,
                                ctx->from_space,
                                .file = ctx->from_space->vtable.debug_name);

    /* Scrub thread lock chains of any entries that live inside the
     * old from-space segments we're about to unmap.  Locks embedded
     * in default-arena allocations (Regex::inner_lock and friends)
     * would otherwise leave dangling heads on rt->threads[i].
     * exclusive_locks. */
    extern void     n00b_lock_chains_scrub_range(uint64_t lo, uint64_t hi);
    n00b_segment_t *seg = (n00b_segment_t *)old_segments;
    while (seg) {
        uintptr_t seg_lo = (uintptr_t)seg;
        uintptr_t seg_hi = seg_lo + seg->size;
        n00b_lock_chains_scrub_range(seg_lo, seg_hi);
        seg = seg->next_segment;
    }

    n00b_allocator_destroy((n00b_allocator_t *)&ctx->work_pool);
    n00b_allocator_destroy((n00b_allocator_t *)ctx->to_space);

    n00b_atomic_fence();
}

// ============================================================================
// Entry point
// ============================================================================

// We do not want the compiler to inline this, otherwise it will quite
// likely blend the stack frame in a way we don't like w/
// n00b_collect().
static __attribute__((noinline)) void
n00b_collect_internal(n00b_arena_t *arena)
{
    n00b_collect_t  ctx;
    n00b_segment_t *segment = arena->current_segment;

    segment->last_addr = n00b_atomic_load(&arena->next_alloc);

    n00b_collect_setup(&ctx, arena);
    arena->alloc_count = 0;

    n00b_scan_roots(&ctx);

    n00b_scan_runtime(&ctx);
    n00b_process_worklist(&ctx);

    n00b_scan_thread_stacks(&ctx);
    n00b_process_worklist(&ctx);

    /* Pool walk as roots: every metadata-bearing pool gives up
     * each of its alive allocs as a root for this mark pass.  This
     * replaces "register the pool's owning struct as a root"
     * callers and is more precise — only the actually-live slots
     * get scanned. The visit path stamps gc_epoch on each alloc
     * reached.
     *
     * In leak-detect mode the runtime caller skips this step: the
     * point of leak detection is precisely to test reachability
     * from the **real** roots only, so that allocations whose only
     * inbound pointer is "they live in a pool" still get classified
     * as leaks. */
    {
        n00b_runtime_t *rt = n00b_get_runtime();
        if (!rt || !n00b_atomic_load(&rt->debug_leak_detect)) {
            n00b_scan_metadata_pools(&ctx);
            n00b_process_worklist(&ctx);
        }
    }

    assert(!n00b_list_len(ctx.worklist));

    /* Sweep stale-epoch alive allocs back to their pools — that
     * set is the leak diagnostic the runtime exposes. */
    n00b_sweep_metadata_pool_leaks(&ctx);

    n00b_process_finalizers(&ctx);

    n00b_collection_cleanup(&ctx);
}

void
n00b_collect(n00b_arena_t *arena)
{
    n00b_jmp_buf_t                     register_spill = {};
    [[maybe_unused]] volatile uint64_t top            = 0;
    volatile n00b_thread_t            *self           = n00b_thread_self();

    self->stack_top = (void *)&top;

    if (!n00b_setjmp(&register_spill)) {
        n00b_collect_internal(arena);
        n00b_longjmp(&register_spill, 1);
    }
}

void
n00b_debug_find_leaks(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    if (!rt) {
        return;
    }

    n00b_arena_t *arena = rt->default_arena;
    if (!arena) {
        return;
    }

    /* Toggle the runtime flag that turns the standard sweep into
     * "print, then reclaim" mode for the duration of one
     * collection. The collect itself drives STW; that handshake is
     * what makes the metadata-pool walk + sweep safe to do without
     * additional locking. */
    n00b_atomic_store(&rt->debug_leak_detect, true);
    n00b_stop_the_world();
    n00b_collect(arena);
    n00b_restart_the_world();
    n00b_atomic_store(&rt->debug_leak_detect, false);
}
