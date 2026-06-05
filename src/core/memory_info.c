#define N00B_MEM_INTERNAL_API
#define N00B_USE_INTERNAL_API

#include <signal.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#else
#include "core/platform.h"
#endif

#include "n00b.h"
#include "core/mmaps.h"
#include "core/alloc_mdata.h"
#include "core/memory_info.h"
#include "core/align.h"
#include "core/atomic.h"
#include "core/thread.h"
#include "core/arena.h"
#include "core/runtime.h"
#include "core/static_objects.h"
#include "adt/interval_tree.h"
#include "adt/variant.h"
#include "text/unicode/encoding.h"
#include "text/unicode/properties.h"

// TODO
// #include "core/stw.h"

// TODO
#define n00b_fprintf fprintf
#include <stdio.h>

_Atomic uint64_t static_order_id = 1;

static inline bool
n00b_mmap_perms_known(n00b_mmap_perms_t perms)
{
    return perms != n00b_mmap_perms_unknown;
}

static inline n00b_mmap_perms_t
n00b_mmap_perms_from_bits(bool readable, bool writable)
{
    if (writable) {
        return n00b_mmap_perms_rw;
    }
    if (readable) {
        return n00b_mmap_perms_ro;
    }
    return n00b_mmap_perms_no_access;
}

#if defined(_WIN32)
static inline n00b_mmap_perms_t
n00b_mmap_perms_from_win_protect(DWORD protect)
{
    if (protect & (PAGE_READWRITE | PAGE_WRITECOPY
                   | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        return n00b_mmap_perms_rw;
    }
    if (protect & (PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE)) {
        return n00b_mmap_perms_ro;
    }
    return n00b_mmap_perms_no_access;
}
#endif

static n00b_memperm_pipe_t *
n00b_memperm_pipe_get(void)
{
    return &n00b_thread_self()->memperm_pipe;
}

extern void n00b_debug_memory_info(bool);

// For right now, this is dumb. But it should ultimately keep sorted
// while inserting, and binary search. Will do that when we move it to
// a proper list.
//
// Note that we never record data ranges; anything not registered as a
// segment by the time a call returns here is considered data.

#define MINCORE_TEST_BIT 1

#if defined(__linux__)
#include <link.h>

static int
n00b_extract_lib_info(struct dl_phdr_info *info, size_t size, void *unused)
{
    int64_t intaddr;
    void   *startp;
    void   *endp;

    for (uint32_t i = 0; i < info->dlpi_phnum; i++) {
        size    = info->dlpi_phdr[i].p_vaddr;
        intaddr = (int64_t)(info->dlpi_addr + size);
        startp  = (void *)intaddr;
        endp    = (void *)(intaddr + info->dlpi_phdr[i].p_memsz);

        if (startp == endp) {
            continue;
        }
        n00b_mmap_perms_t perms = startp
                                    ? n00b_mmap_perms_from_bits(
                                          (info->dlpi_phdr[i].p_flags & PF_R) != 0,
                                          (info->dlpi_phdr[i].p_flags & PF_W) != 0)
                                    : n00b_mmap_perms_no_access;
        (void)n00b_mmap_register(startp,
                                 endp,
                                 startp ? n00b_mmap_static : n00b_mmap_zero_page,
                                 .file              = (char *)info->dlpi_name,
                                 .binary_offset     = info->dlpi_phdr[i].p_offset,
                                 .slide             = -(intptr_t)info->dlpi_addr,
                                 .order_id          = n00b_atomic_add(&static_order_id, 1),
                                 .perms             = perms,
                                 .definitely_unique = false);
    }
    return 0;
}

#if defined(N00B_ALWAYS_RECHECK_STATIC_POINTERS)
static inline n00b_option_t(n00b_mmap_info_t *)
n00b_check_static_maps(void *addr)
{
    dl_iterate_phdr(n00b_extract_lib_info, nullptr);
    return n00b_mmap_by_address(addr);
}
#endif

void
n00b_load_static_ranges(void)
{
    dl_iterate_phdr(n00b_extract_lib_info, nullptr);
    (void)n00b_static_objects_register_all();
}

#elifdef __APPLE__
#include <dlfcn.h>         // for dladdr, Dl_info
#include <mach-o/dyld.h>   // for _dyld_register_func_for_add_image
#include <mach-o/loader.h> // for segment_command_64, mach_header_64, LC_...
#include <mach/vm_prot.h>

void
n00b_on_lib_load(const struct mach_header *hdr, intptr_t slide)
{
    if (hdr->magic != MH_MAGIC_64) {
        n00b_fprintf(stderr, "Only 64-bit supported.\n");
        abort();
    }

    struct mach_header_64     *header  = (struct mach_header_64 *)hdr;
    char                      *start   = (char *)&header[1];
    struct segment_command_64 *command = (struct segment_command_64 *)start;

    Dl_info info;
    dladdr(header, &info);

    for (uint32_t i = 0; i < header->ncmds; i++) {
        uint64_t seg_start = command->vmaddr + slide;
        uint64_t seg_end   = seg_start + command->vmsize;

        if (command->cmd == LC_SEGMENT_64 && seg_start != seg_end) {
            n00b_mmap_perms_t perms = seg_start
                                        ? n00b_mmap_perms_from_bits(
                                              (command->initprot & VM_PROT_READ) != 0,
                                              (command->initprot & VM_PROT_WRITE) != 0)
                                        : n00b_mmap_perms_no_access;
            (void)n00b_mmap_register((void *)seg_start,
                                     (void *)seg_end,
                                     seg_start ? n00b_mmap_static : n00b_mmap_zero_page,
                                     .file              = (char *)info.dli_fname,
                                     .binary_offset     = command->fileoff,
                                     .slide             = -slide,
                                     .order_id          = n00b_atomic_add(&static_order_id, 1),
                                     .perms             = perms,
                                     .definitely_unique = false);
            assert(static_order_id != 1);
        }

        start += command->cmdsize;
        command = (void *)start;
    }

    (void)n00b_static_objects_register_macho_image(hdr, slide);
}

void
n00b_load_static_ranges(void)
{
    _dyld_register_func_for_add_image(n00b_on_lib_load);
}
#elifdef _WIN32

void
n00b_load_static_ranges(void)
{
    (void)n00b_static_objects_register_all();
}

#else
#error "Unsupported OS"
#endif

static n00b_option_t(n00b_mmap_info_t *)
n00b_check_kernel_page_map(const void *addr)
{
    char              *start = n00b_align_to_page_start((void *)addr);
    n00b_mmap_perms_t perms  = n00b_mmap_perms_unknown;

    if (!start) {
        return n00b_option_none(n00b_mmap_info_t *);
    }

#ifdef _WIN32
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(start, &mbi, sizeof(mbi))) {
        return n00b_option_none(n00b_mmap_info_t *);
    }
    if (mbi.State != MEM_COMMIT) {
        return n00b_option_none(n00b_mmap_info_t *);
    }
    perms = n00b_mmap_perms_from_win_protect(mbi.Protect);
#else
    char status[1];
    // This cast is crucial due to different signatures across
    // mac + linux (signed vs. unsigned.
    if (mincore(start, n00b_page_size, (void *)status)) {
        return n00b_option_none(n00b_mmap_info_t *);
    }
    if (!(status[0] & MINCORE_TEST_BIT)) {
        return n00b_option_none(n00b_mmap_info_t *);
    }
#endif

    // Register just this one page.
    return n00b_mmap_register(start,
                              start + n00b_page_size,
                              start ? n00b_mmap_unmanaged : n00b_mmap_zero_page,
                              .perms             = start ? perms : n00b_mmap_perms_no_access,
                              .definitely_unique = false);
}

// This only gets called when lookup fails.
static inline n00b_option_t(n00b_mmap_info_t *)
n00b_check_for_unmanaged_map(const void *addr)
{
    n00b_option_t(n00b_mmap_info_t *) result;
    // On MacOS, we register for dynamic events, so don't need to make a
    // dynamic call; it would have been in the static list (minux some
    // race condition, where we'll just accept returning that an address
    // is data).
    //
    // On Linux, I recommend not turning on this re-checking; we
    // expose the ability to manually re-run (call
    // n00b_reload_static_ranges() yourself).

#if defined(__linux__) && defined(N00B_ALWAYS_RECHECK_STATIC_POINTERS)
    result = n00b_check_static_maps(addr);
    if (n00b_option_is_set(result)) {
        return result;
    }
#endif

    result = n00b_check_kernel_page_map(addr);

    return result;
}

n00b_option_t(n00b_mmap_info_t *)
n00b_mmap_info_lookup(const void *addr)
{
    auto result = n00b_mmap_by_address((void *)addr);

    if (n00b_option_is_set(result)) {
        if (n00b_option_get(result)->kind == n00b_mmap_zero_page) {
            return n00b_option_none(n00b_mmap_info_t *);
        }
        return result;
    }

    return n00b_check_for_unmanaged_map(addr);
}

// clang-format off
n00b_option_t(n00b_allocator_t *)
n00b_find_allocator(void *val)
{
    auto mmap_opt = n00b_mmap_info_lookup(val);

    if (!n00b_option_is_set(mmap_opt)) {
        return n00b_option_none(n00b_allocator_t *);
    }

    n00b_mmap_info_t *mmap = n00b_option_get(mmap_opt);
    return n00b_option_from_nullable(n00b_allocator_t *, atomic_load(&mmap->allocator));
}
// clang-format on

n00b_mmap_perms_t
n00b_check_memory_perms(void *ptr)
{
    auto map_opt = n00b_mmap_by_address(ptr);
    if (n00b_option_is_set(map_opt)) {
        n00b_mmap_info_t *map = n00b_option_get(map_opt);
        if (map->kind == n00b_mmap_zero_page) {
            return n00b_mmap_perms_no_access;
        }
        if (n00b_mmap_perms_known(map->perms)) {
            return map->perms;
        }
    }

#ifdef _WIN32
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(ptr, &mbi, sizeof(mbi))) {
        return n00b_mmap_perms_no_access;
    }
    if (mbi.State != MEM_COMMIT) {
        return n00b_mmap_perms_no_access;
    }
    return n00b_mmap_perms_from_win_protect(mbi.Protect);
#else
    bool cannot_write = false;
    bool cannot_read  = false;

    n00b_memperm_pipe_t *pipe_state = n00b_memperm_pipe_get();
    int                  local_pipe_fds[2];
    int                 *pipe_fds  = local_pipe_fds;
    bool                 use_cache = false;

    signal(SIGPIPE, SIG_IGN);

    if (pipe_state) {
        if (!pipe_state->ready) {
            if (pipe(pipe_state->fds)) {
                return n00b_mmap_perms_no_access;
            }
            int flags = fcntl(pipe_state->fds[0], F_GETFL, 0);
            if (flags >= 0) {
                fcntl(pipe_state->fds[0], F_SETFL, flags | O_NONBLOCK);
            }
            pipe_state->ready = 1;
        }
        pipe_fds  = pipe_state->fds;
        use_cache = true;
    }
    else {
        if (pipe(local_pipe_fds)) {
            return n00b_mmap_perms_no_access;
        }
        int flags = fcntl(local_pipe_fds[0], F_GETFL, 0);
        if (flags >= 0) {
            fcntl(local_pipe_fds[0], F_SETFL, flags | O_NONBLOCK);
        }
    }

    ssize_t wrc = write(pipe_fds[1], ptr, 1);
    if (wrc <= 0) {
        cannot_write = true;
    }

    struct pollfd pollset = {
        .fd     = pipe_fds[0],
        .events = POLL_IN,
    };

    int prc = poll(&pollset, 1, 0);
    if (prc <= 0 || !(pollset.revents & POLL_IN)) {
        cannot_read = true;
        char drain;
        (void)read(pipe_fds[0], &drain, 1);
    }
    else {
        ssize_t rrc = read(pipe_fds[0], ptr, 1);
        if (rrc <= 0) {
            cannot_read = true;
            char drain;
            (void)read(pipe_fds[0], &drain, 1);
        }
    }

    if (!use_cache) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
    }

    if (cannot_write) {
        if (cannot_read) {
            return n00b_mmap_perms_no_access;
        }
        else {
            return n00b_mmap_perms_ro;
        }
    }

    return n00b_mmap_perms_rw;
#endif
}

static inline bool
codepoint_is_printable(int32_t cp)
{
    switch (n00b_unicode_general_category((n00b_codepoint_t)cp)) {
    case N00B_UNICODE_GC_CC: // Control
    case N00B_UNICODE_GC_CF: // Format
    case N00B_UNICODE_GC_CS: // Surrogate
        return false;
    default:
        // Reject whitespace other than plain space.
        if (cp != ' ') {
            n00b_unicode_gc_t gc = n00b_unicode_general_category((n00b_codepoint_t)cp);
            if (gc == N00B_UNICODE_GC_ZS || gc == N00B_UNICODE_GC_ZL
                || gc == N00B_UNICODE_GC_ZP) {
                return false;
            }
        }
        return true;
    }
}

size_t
n00b_address_is_probable_cstring(void *addr, size_t *bytelen, size_t min_len)
{
    // Looks for valid UTF-8 with null termination and printable content.
    // Returns the codepoint count (0 if not a plausible string).

    char *base      = (char *)addr;
    char *page_end;
    char *p         = base;

    if (n00b_value_is_data(p)) {
        return 0;
    }

    page_end = (char *)n00b_align_to_page_start(p) + n00b_page_size;

    // We decode one page at a time; within each page we use the new
    // n00b_unicode_utf8_decode() which takes (base, len, &pos).
    uint32_t total_bytes = 0;
    uint32_t total_cp    = 0;

    while (true) {
        uint32_t chunk_len = (uint32_t)(page_end - p);
        uint32_t pos       = 0;

        while (pos < chunk_len) {
            // Check for NUL terminator before decoding.
            if (p[pos] == '\0') {
                uint32_t blen = total_bytes + pos;
                if (total_cp < min_len) {
                    return 0;
                }
                *bytelen = blen;
                return total_cp;
            }

            int32_t cp = n00b_unicode_utf8_decode(p, chunk_len, &pos);
            if (cp < 0) {
                return 0;
            }
            if (!codepoint_is_printable(cp)) {
                return 0;
            }
            total_cp++;
        }

        total_bytes += chunk_len;
        p = page_end;
        page_end += n00b_page_size;

        if (n00b_value_is_data(p)) {
            return 0;
        }
    }
}

bool
n00b_memory_scan_init(n00b_memory_scan_t *ctx, void *s, size_t len) _kargs
{
    uint8_t cat_flags = 0;
}
{
    uint64_t start = (uint64_t)s;
    uint64_t end   = start + len;

    ctx->cur = (uint64_t *)n00b_align_ceil(start, sizeof(void *));
    ctx->end = (uint64_t *)n00b_align_floor(end, sizeof(void *));

    if (n00b_value_is_data(ctx->cur) || n00b_value_is_data(ctx->end)) {
        return false;
    }

    if (!cat_flags) {
        ctx->flags = n00b_mmap_type_mask;
    }
    else {
        ctx->flags = cat_flags;
    }

    return true;
}

n00b_option_t(void *)
n00b_memory_scan_next(n00b_memory_scan_t   *ctx,
                      n00b_mmap_rec_kind_t *tinfo,
                      n00b_mmap_perms_t    *perms)
{
    void             *result = nullptr;
    void             *target = nullptr;
    n00b_mmap_info_t *mmap   = nullptr;

    while (!result && (ctx->cur < ctx->end)) {
        void *val     = (void *)*ctx->cur;
        auto  mmap_opt = n00b_mmap_info_lookup(val);

        if (n00b_option_is_set(mmap_opt)) {
            mmap = n00b_option_get(mmap_opt);
            if (mmap->kind & ctx->flags) {
                result   = (void *)ctx->cur;
                target   = val;
                ctx->cur = ctx->cur + 1;
                break;
            }
        }
        mmap     = nullptr;
        ctx->cur = ctx->cur + 1;
    }

    if (!mmap) {
        return n00b_option_none(void *);
    }

    if (perms) {
        *perms = n00b_check_memory_perms(target);
    }

    if (tinfo) {
        *tinfo = mmap->kind;
    }

    return n00b_option_set(void *, result);
}

static void
show_mem_info(n00b_mmap_info_t *n, bool all, unsigned int *lenp)
{
    char *kind_str = nullptr;
    bool  aseg     = false;

    if (!n) {
        return;
    }

    switch (n->kind) {
    case n00b_mmap_static:
        if (!all) {
            return;
        }
        else {
            kind_str = "Static memory ";
        }
        break;
    case n00b_mmap_arena:
        kind_str = "Arena header   "; // Currently not being registered.
        *lenp += (n->end - n->start);
        break;
    case n00b_mmap_managed_segment:
        kind_str = "Arena segment  ";
        *lenp += (n->end - n->start);
        aseg = true;
        break;
    case n00b_mmap_sys_segment:
        kind_str = "Sys segment    ";
        *lenp += (n->end - n->start);
        aseg = true;
        break;
    case n00b_mmap_stack:
        kind_str = "Thread stack   ";
        break;
    case n00b_mmap_unmanaged:
        *lenp += (n->end - n->start);
        kind_str = "Unmanaged heap ";
        break;
    case n00b_mmap_internal:
        *lenp += (n->end - n->start);
        kind_str = "N00b internal  ";
        break;
    case n00b_mmap_zero_page:
        kind_str = "Inaccessible   ";
        break;
    case n00b_mmap_pool:
        kind_str = "Pool alloc     ";
        *lenp += (n->end - n->start);
        aseg = true;
        break;
    case n00b_mmap_api_mmap:
        kind_str = "n00b_mmap()    ";
        *lenp += (n->end - n->start);
        break;
    default:
        abort();
    }

    n00b_allocator_t *a    = n->allocator;
    const char       *file = "(no file)";
    if (n->file) {
        file = n->file;
    }

    if (aseg) {
        if (!a->metadata) {
            n00b_fprintf(stderr,
                         "%s %s %p-%p (%'llu bytes, %'zu pages) arena @ %p (%s)\n",
                         kind_str,
                         file,
                         (void *)n->start,
                         (void *)n->end,
                         (unsigned long long)(n->end - n->start),
                         (size_t)(n->end - n->start) / n00b_page_size,
                         a,
                         n->file ? n->file : "*no name*");
        }
        else {
            n00b_allocator_t *link = a->metadata_pool;

            n00b_fprintf(stderr,
                         "%s %s %p-%p (%'llu bytes, %'zu pages) arena @ "
                         "%p (alloc mdata for arena '%s' @%p)\n",
                         kind_str,
                         file,
                         (void *)n->start,
                         (void *)n->end,
                         (unsigned long long)(n->end - n->start),
                         (unsigned int)(n->end - n->start) / n00b_page_size,
                         a,
                         link->debug_name ? link->debug_name : "*no name*",
                         link);
        }
    }
    else {
        n00b_fprintf(stderr,
                     "%s %s %p-%p (%'llu bytes, %'zu pages)\n",
                     kind_str,
                     file,
                     (void *)n->start,
                     (void *)n->end,
                     (unsigned long long)(n->end - n->start),
                     (unsigned int)(n->end - n->start) / n00b_page_size);
    }
}

void
n00b_debug_memory_info(bool all)
{
    unsigned int     len = 0;
    n00b_mmap_ctx_t *ctx = n00b_global_mem_map(n00b_get_runtime());

    n00b_allocator_t *alloc = (n00b_allocator_t *)&ctx->pool;
    n00b_stack_t(void *) results = n00b_stack_new(void *, .allocator = alloc);

    (void)n00b_interval_search_ordered(ctx->mmap_tree, 0, UINT64_MAX, &results);

    for (size_t i = 0; i < n00b_stack_len(results); i++) {
        auto node = results.data[i];
        n00b_mmap_data_t data = ((n00b_interval_node_t(n00b_mmap_data_t) *)node)->data;
        assert(n00b_variant_is_type(data, n00b_mmap_info_t *));
        show_mem_info(n00b_variant_get(data, n00b_mmap_info_t *), all, &len);
    }

    n00b_fprintf(stderr,
                 "\nTotal heap usage: %'u bytes (%'zu pages)\n",
                 len,
                 len / n00b_page_size);
}
