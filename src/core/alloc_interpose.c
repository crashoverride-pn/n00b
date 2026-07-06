// alloc_interpose.c — plain-C ABI shim (§11). This file (and its header
// include/core/alloc_interpose.h) is a libc-ABI boundary: it DEFINES the libc
// malloc family, so libc-shaped signatures (`char *strdup(const char *)`, the
// raw malloc/free prototypes) and direct use of leaf libc string routines are
// allowed HERE and only here. Internal libn00b code uses the n00b surface.
//
// libc malloc-family interposition routed through n00b's current/default
// allocator.
//
// See include/core/alloc_interpose.h for the rationale, lifecycle, and
// per-platform install mechanisms.
//
// Design notes:
//   * Post-init allocations go through the normal n00b allocator API on
//     the thread's current/default allocator. Plain
//     malloc/calloc return the exact allocation base so legacy n00b-side
//     callers that release picotls output with n00b_free() remain correct.
//     Explicitly over-aligned APIs may return an interior aligned pointer;
//     free/realloc recover the real base from n00b metadata while the runtime
//     is live.
//   * Pre-init (before the runtime allocators exist) we delegate to the real
//     libc symbols, resolved via dlsym(RTLD_NEXT). Those run on the main
//     thread with a full TCB, so libc is safe there. A small static
//     bootstrap arena satisfies any malloc that occurs *during* the dlsym
//     resolution itself (the classic interposer reentrancy window).
//   * free()/realloc() classify a pointer by address while the runtime is
//     live: bootstrap arena → no-op/copy; n00b-owned interpose range → recover
//     base + n00b_free; otherwise a pre-init libc pointer → real libc
//     free/realloc. A static page-range table identifies late process-exit
//     frees after shutdown without touching runtime state; those frees become
//     no-ops.
//   * memcpy/memset/strlen/strnlen are leaf libc routines (no allocation, no
//     TSD/pthread_self), so they are safe to call on off-libc workers; this
//     is the libc boundary, so using them here is intentional, not a stdlib
//     substitution.

#include <dlfcn.h>
#include <string.h>
#include <stdatomic.h>
#include <errno.h>
#include <stdlib.h>
#if defined(__linux__)
#include <malloc.h>
#endif

#include "n00b.h"
#include "core/alloc.h"
#include "core/alloc_mdata.h"
#include "core/align.h"
#include "core/mmaps.h"
#include "core/pool.h"
#include "core/runtime.h"
#include "adt/option.h"
#include "util/panic.h"
#include "core/alloc_interpose.h"

// ============================================================================
// Hit counter (drives the interposition self-test).
// ============================================================================

static _Atomic uint64_t n00b_interpose_hit_count = 0;

uint64_t
n00b_alloc_interpose_hits(void)
{
    return atomic_load(&n00b_interpose_hit_count);
}

#define N00B_INTERPOSE_BUMP() atomic_fetch_add(&n00b_interpose_hit_count, 1)

// ============================================================================
// Real-libc resolution + pre-init bootstrap arena.
// ============================================================================

static void *(*real_malloc)(size_t)         = nullptr;
static void (*real_free)(void *)            = nullptr;
static void *(*real_calloc)(size_t, size_t) = nullptr;
static void *(*real_realloc)(void *, size_t) = nullptr;
static int (*real_posix_memalign)(void **, size_t, size_t) = nullptr;
static void *(*real_aligned_alloc)(size_t, size_t)         = nullptr;
static size_t (*real_malloc_usable_size)(void *)           = nullptr;
#if defined(__linux__)
static void *(*real_memalign)(size_t, size_t) = nullptr;
static void *(*real_valloc)(size_t)           = nullptr;
static void *(*real_pvalloc)(size_t)          = nullptr;
#endif

static _Atomic bool reals_ready = false;
static _Atomic bool reals_busy  = false;
static _Atomic bool process_exiting = false;
static _Atomic bool runtime_may_be_live = false;
static _Atomic bool exit_guard_registered = false;

// Satisfies allocations that happen while dlsym() itself is resolving the
// real symbols. This window is tiny and single-threaded (process startup),
// so a fixed bump arena is sufficient; it is never freed.
#define N00B_BOOTSTRAP_SZ (1 << 16) // 64 KiB
static char            n00b_bootstrap_arena[N00B_BOOTSTRAP_SZ];
static _Atomic size_t  n00b_bootstrap_off = 0;

static inline bool
in_bootstrap(const void *p)
{
    return (const char *)p >= n00b_bootstrap_arena
        && (const char *)p < n00b_bootstrap_arena + N00B_BOOTSTRAP_SZ;
}

static void *
bootstrap_alloc(size_t n)
{
    n          = (n + 15) & ~(size_t)15; // 16-byte aligned
    size_t off = atomic_fetch_add(&n00b_bootstrap_off, n);
    if (off + n > N00B_BOOTSTRAP_SZ) {
        return nullptr; // bootstrap exhausted (should never happen)
    }
    return n00b_bootstrap_arena + off; // already zero (static storage)
}

static void
mark_process_exiting(void)
{
    atomic_store(&process_exiting, true);
    atomic_store(&runtime_may_be_live, false);
}

static void
register_exit_guard_once(void)
{
    bool expected = false;
    if (atomic_compare_exchange_strong(&exit_guard_registered, &expected, true)) {
        (void)atexit(mark_process_exiting);
    }
}

static void
ensure_reals(void)
{
    if (atomic_load(&reals_ready)) {
        return;
    }
    // This runs only PRE-INIT, which is single-threaded: the runtime (and
    // hence n00b's worker threads) does not exist yet, so there is no true
    // multi-thread race here. `reals_busy` is NOT a mutex — it is a
    // single-stack recursion guard: if dlsym() itself calls malloc while we
    // are resolving, that reentrant malloc sees reals_busy and falls to the
    // bootstrap arena instead of recursing. (A would-be concurrent caller is
    // impossible at this point; if that ever changes, this needs a real once.)
    if (atomic_exchange(&reals_busy, true)) {
        return;
    }

    real_malloc  = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
    real_free    = (void (*)(void *))dlsym(RTLD_NEXT, "free");
    real_calloc  = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
    real_realloc = (void *(*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
    real_posix_memalign =
        (int (*)(void **, size_t, size_t))dlsym(RTLD_NEXT, "posix_memalign");
    real_aligned_alloc =
        (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "aligned_alloc");
    real_malloc_usable_size =
        (size_t (*)(void *))dlsym(RTLD_NEXT, "malloc_usable_size");
#if defined(__linux__)
    real_memalign = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "memalign");
    real_valloc   = (void *(*)(size_t))dlsym(RTLD_NEXT, "valloc");
    real_pvalloc  = (void *(*)(size_t))dlsym(RTLD_NEXT, "pvalloc");
#endif

    atomic_store(&reals_ready, true);
    atomic_store(&reals_busy, false);
}

// ============================================================================
// User-pool routing.
// ============================================================================

static inline bool
runtime_ready(void)
{
    return !atomic_load(&process_exiting)
        && atomic_load(&runtime_may_be_live)
        && n00b_default_runtime_is_set()
        && atomic_load(&n00b_get_runtime()->startup_complete);
}

void
n00b_alloc_interpose_runtime_start(void)
{
    register_exit_guard_once();
    atomic_store(&process_exiting, false);
    atomic_store(&runtime_may_be_live, true);
}

void
n00b_alloc_interpose_runtime_stop(void)
{
    atomic_store(&runtime_may_be_live, false);
}

static bool interpose_range_contains(void *ptr);

// True if `p` points anywhere inside an allocation page handed out by this
// interposer while the runtime is live.
static inline bool
owned_by_interpose_allocation(void *p)
{
    n00b_allocator_opt_t a = n00b_mem_get_allocator(p);
    return n00b_option_is_set(a) && interpose_range_contains(p);
}

// Recover the allocation start for a pointer known to live inside an interposed
// allocation page. Inline-header allocators can recover by scanning back to the
// inline header; OOB allocators are exact-base keyed, so over-aligned pointers
// need the bounded downward probe below.
// Backstop for the downward probe. For our own allocations the base is at
// most (requested alignment - N00B_ALIGN) below the returned pointer; a
// normal (non-over-aligned) allocation hits on the first probe. The cap only
// bounds the loop for a corrupt/foreign pointer that nonetheless resolves to
// a n00b allocator page. 64 KiB comfortably covers any realistic alignment request
// (page alignment and below) while keeping the worst case bounded.
#define N00B_INTERPOSE_MAX_ALIGN_PROBE (1 << 16)
static void *
recover_pool_base(void *p)
{
    n00b_alloc_info_t direct = n00b_find_alloc_info(p, .scan_for_header = true);
    if (direct.kind == n00b_alloc_inline) {
        return (char *)direct.hdr.in_line + N00B_ALLOC_HDR_SZ;
    }
    if (direct.kind == n00b_alloc_oob) {
        return direct.hdr.oob->user_ptr;
    }

    uintptr_t addr = (uintptr_t)p;
    uintptr_t low  = (addr >= N00B_INTERPOSE_MAX_ALIGN_PROBE)
                       ? addr - N00B_INTERPOSE_MAX_ALIGN_PROBE
                       : 0;

    for (uintptr_t cand = addr; cand >= low; cand -= N00B_ALIGN) {
        n00b_alloc_info_t info = n00b_find_alloc_info((void *)cand);
        if (info.kind == n00b_alloc_oob) {
            // OOB metadata is keyed by the exact base, so a hit means
            // `cand` is an allocation start.
            return info.hdr.oob->user_ptr;
        }
        if (cand < N00B_ALIGN) {
            break;
        }
    }
    return nullptr;
}

static size_t
interpose_usable_from_info(n00b_alloc_info_t info)
{
    switch (info.kind) {
    case n00b_alloc_inline:
        return info.hdr.in_line->alloc_len > N00B_ALLOC_HDR_SZ
                   ? info.hdr.in_line->alloc_len - N00B_ALLOC_HDR_SZ
                   : 0;
    case n00b_alloc_oob:
        if (info.hdr.oob->hcur != nullptr) {
            return info.hdr.oob->alloc_len > N00B_ALLOC_HDR_SZ
                       ? info.hdr.oob->alloc_len - N00B_ALLOC_HDR_SZ
                       : 0;
        }
        return info.hdr.oob->alloc_len;
    default:
        return 0;
    }
}

#define N00B_INTERPOSE_MAX_RANGES 65536

typedef struct {
    uintptr_t start;
    uintptr_t end;
} n00b_interpose_range_t;

static n00b_interpose_range_t interpose_ranges[N00B_INTERPOSE_MAX_RANGES];
static _Atomic size_t         interpose_range_count = 0;
static _Atomic uint32_t       interpose_range_lock  = 0;

static inline void
range_lock(void)
{
    while (atomic_exchange(&interpose_range_lock, 1) != 0) {
    }
}

static inline void
range_unlock(void)
{
    atomic_store(&interpose_range_lock, 0);
}

static bool
interpose_range_contains(void *ptr)
{
    uintptr_t p = (uintptr_t)ptr;
    size_t    n = atomic_load(&interpose_range_count);

    for (size_t i = 0; i < n; i++) {
        if (p >= interpose_ranges[i].start && p < interpose_ranges[i].end) {
            return true;
        }
    }
    return false;
}

static void
remember_interpose_range(void *ptr)
{
    if (!runtime_ready()) {
        return;
    }

    auto opt = n00b_mmap_by_address(ptr);
    if (!n00b_option_is_set(opt)) {
        return;
    }

    n00b_mmap_info_t *info  = n00b_option_get(opt);
    uintptr_t         start = (uintptr_t)info->start;
    uintptr_t         end   = (uintptr_t)info->end;

    range_lock();
    size_t n = atomic_load(&interpose_range_count);
    for (size_t i = 0; i < n; i++) {
        if (interpose_ranges[i].start == start && interpose_ranges[i].end == end) {
            range_unlock();
            return;
        }
    }
    if (n < N00B_INTERPOSE_MAX_RANGES) {
        interpose_ranges[n] = (n00b_interpose_range_t){
            .start = start,
            .end   = end,
        };
        atomic_store(&interpose_range_count, n + 1);
    }
    range_unlock();
}

static inline uintptr_t
align_up_addr(uintptr_t addr, size_t align)
{
    return (addr + (align - 1)) & ~(uintptr_t)(align - 1);
}

// libn00b's sole conservative, type-erased allocation. The libc-malloc
// interposer backs raw malloc(), so it genuinely has no element type to record
// and cannot use a typed n00b_alloc* macro; this is the one sanctioned direct
// use of the raw allocator primitive. Everything else must allocate typed so
// the GC scans precisely and the block is marshalable.
static void *
interpose_alloc_untyped(size_t n, size_t sz, n00b_alloc_opts_t *opts)
{
    return _n00b_alloc_raw(n, sz, 0, N00B_LOC_STRING(), opts);
}

static void *
pool_alloc_for_libc(size_t size, size_t align)
{
    if (!runtime_ready()) {
        return nullptr;
    }

    if (align < N00B_ALIGN) {
        align = N00B_ALIGN;
    }

    size_t payload = size ? size : 1;
    size_t request = payload;
    if (align > N00B_ALIGN
        && __builtin_add_overflow(request, align - N00B_ALIGN, &request)) {
        return nullptr;
    }

    void *base = interpose_alloc_untyped(request, 1, nullptr);
    if (base == nullptr) {
        return nullptr;
    }
    register_exit_guard_once();
    remember_interpose_range(base);

    if (align <= N00B_ALIGN) {
        return base;
    }
    return (void *)align_up_addr((uintptr_t)base, align);
}

// ============================================================================
// The interposed malloc family.
// ============================================================================

void *
n00b_interposed_malloc(size_t size)
{
    N00B_INTERPOSE_BUMP();

    void *pool_ptr = pool_alloc_for_libc(size, N00B_ALIGN);
    if (pool_ptr) {
        return pool_ptr;
    }

    ensure_reals();
    if (real_malloc) {
        return real_malloc(size);
    }
    return bootstrap_alloc(size ? size : 1);
}

void
n00b_interposed_free(void *ptr)
{
    N00B_INTERPOSE_BUMP();

    if (ptr == nullptr) {
        return;
    }
    if (in_bootstrap(ptr)) {
        return; // bootstrap arena is never freed
    }

    bool live = runtime_ready();
    if (live && owned_by_interpose_allocation(ptr)) {
        void *base = recover_pool_base(ptr);
        if (base) {
            n00b_free(base);
            return;
        }
        // Owned-but-unrecoverable: the pointer is inside an interposed n00b
        // page but no allocation base was found within the probe window. Don't
        // hand a n00b pointer to libc; make the anomaly loud instead.
        n00b_panic("alloc_interpose: free of an unrecoverable n00b "
                   "pointer «#»",
                   (int64_t)(uintptr_t)ptr);
    }

    if (!live && interpose_range_contains(ptr)) {
        return;
    }

    // A pointer handed out before the runtime existed: real libc owns it.
    ensure_reals();
    if (real_free) {
        real_free(ptr);
    }
}

void *
n00b_interposed_calloc(size_t count, size_t size)
{
    N00B_INTERPOSE_BUMP();

    size_t total;
    if (__builtin_mul_overflow(count, size, &total)) {
        return nullptr;
    }

    // n00b allocations are zero-filled.
    void *pool_ptr = pool_alloc_for_libc(total, N00B_ALIGN);
    if (pool_ptr) {
        return pool_ptr;
    }

    ensure_reals();
    if (real_calloc) {
        return real_calloc(count, size);
    }
    return bootstrap_alloc(total ? total : 1); // bootstrap arena is zeroed
}

void *
n00b_interposed_realloc(void *ptr, size_t size)
{
    N00B_INTERPOSE_BUMP();

    if (ptr == nullptr) {
        return n00b_interposed_malloc(size);
    }
    if (size == 0) {
        n00b_interposed_free(ptr);
        return n00b_interposed_malloc(1);
    }

    if (in_bootstrap(ptr)) {
        // Bootstrap pointers carry no size; copy conservatively, bounded to
        // the arena. This path is effectively unreachable (bootstrap allocs
        // are tiny startup objects, never realloc'd before reals are ready).
        void *np = n00b_interposed_malloc(size);
        if (np) {
            size_t avail = (size_t)(n00b_bootstrap_arena + N00B_BOOTSTRAP_SZ
                                    - (char *)ptr);
            memcpy(np, ptr, size < avail ? size : avail);
        }
        return np;
    }

    bool live = runtime_ready();
    if (live && owned_by_interpose_allocation(ptr)) {
        void *base = recover_pool_base(ptr);
        if (base) {
            size_t prefix = (size_t)((char *)ptr - (char *)base);
            n00b_alloc_info_t info = n00b_find_alloc_info(
                base, .scan_for_header = true);
            size_t old = interpose_usable_from_info(info);
            old           = (old > prefix) ? old - prefix : 0;

            void *np = n00b_interposed_malloc(size);
            if (np) {
                memcpy(np, ptr, old < size ? old : size);
                n00b_free(base);
            }
            return np;
        }
        // Owned-but-unrecoverable (see n00b_interposed_free): returning NULL
        // here while the caller still holds an unfreeable pool pointer would
        // be a silent leak + the classic realloc-returns-NULL footgun. Treat
        // it as the invariant violation it is.
        n00b_panic("alloc_interpose: realloc of an unrecoverable n00b "
                   "pointer «#»",
                   (int64_t)(uintptr_t)ptr);
    }

    if (!live && interpose_range_contains(ptr)) {
        return nullptr;
    }

    ensure_reals();
    if (real_realloc) {
        return real_realloc(ptr, size);
    }
    return nullptr;
}

void *
n00b_interposed_reallocarray(void *ptr, size_t count, size_t size)
{
    N00B_INTERPOSE_BUMP();

    size_t total;
    if (__builtin_mul_overflow(count, size, &total)) {
        return nullptr; // (errno deliberately untouched: it is TLS-backed)
    }
    // n00b_interposed_realloc bumps again; double-counting the hit is
    // harmless (the counter is only a liveness signal for the probe).
    return n00b_interposed_realloc(ptr, total);
}

char *
n00b_interposed_strdup(const char *s)
{
    if (s == nullptr) {
        return nullptr;
    }
    size_t n = strlen(s) + 1;
    char  *p = n00b_interposed_malloc(n);
    if (p) {
        memcpy(p, s, n);
    }
    return p;
}

char *
n00b_interposed_strndup(const char *s, size_t n)
{
    if (s == nullptr) {
        return nullptr;
    }
    size_t len = strnlen(s, n);
    char  *p   = n00b_interposed_malloc(len + 1);
    if (p) {
        memcpy(p, s, len);
        p[len] = '\0';
    }
    return p;
}

// Over-aligned allocation: n00b allocators guarantee only N00B_ALIGN (32-byte)
// alignment, so for a larger request we over-allocate enough slack and return
// an aligned interior pointer. free/realloc recover the pool base via OOB
// metadata while the runtime is live.
static void *
aligned_from_pool(size_t align, size_t size)
{
    void *pool_ptr = pool_alloc_for_libc(size, align);
    if (!pool_ptr) {
        ensure_reals();
        void *p = nullptr;
        if (real_posix_memalign) {
            if (real_posix_memalign(&p, align, size) == 0) {
                return p;
            }
        }
        if (real_aligned_alloc && (size % align) == 0) {
            return real_aligned_alloc(align, size);
        }
#if defined(__linux__)
        if (real_memalign) {
            return real_memalign(align, size);
        }
#endif
        return p;
    }
    return pool_ptr;
}

int
n00b_interposed_posix_memalign(void **memptr, size_t align, size_t size)
{
    N00B_INTERPOSE_BUMP();

    // align must be a power of two and a multiple of sizeof(void *).
    if (memptr == nullptr || (align % sizeof(void *)) != 0
        || (align & (align - 1)) != 0 || align == 0) {
        return EINVAL;
    }

    void *p = aligned_from_pool(align, size);
    if (p == nullptr) {
        return ENOMEM;
    }
    *memptr = p;
    return 0;
}

void *
n00b_interposed_aligned_alloc(size_t align, size_t size)
{
    N00B_INTERPOSE_BUMP();

    if (align == 0 || (align & (align - 1)) != 0) {
        return nullptr; // alignment must be a non-zero power of two
    }
    return aligned_from_pool(align, size);
}

size_t
n00b_interposed_malloc_usable_size(void *ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    if (in_bootstrap(ptr)) {
        return 0; // unknown; conservative
    }
    bool live = runtime_ready();
    if (live && owned_by_interpose_allocation(ptr)) {
        void *base = recover_pool_base(ptr);
        if (base) {
            size_t prefix = (size_t)((char *)ptr - (char *)base);
            n00b_alloc_info_t info = n00b_find_alloc_info(
                base, .scan_for_header = true);
            size_t usable = interpose_usable_from_info(info);
            return usable > prefix ? usable - prefix : 0;
        }
    }
    if (!live && interpose_range_contains(ptr)) {
        return 0;
    }
    ensure_reals();
    if (real_malloc_usable_size) {
        return real_malloc_usable_size(ptr);
    }
    return 0;
}

#if defined(__linux__)

void *
n00b_interposed_memalign(size_t align, size_t size)
{
    N00B_INTERPOSE_BUMP();

    if (align == 0 || (align & (align - 1)) != 0) {
        return nullptr;
    }
    if (align < sizeof(void *)) {
        align = sizeof(void *);
    }
    return aligned_from_pool(align, size);
}

void *
n00b_interposed_valloc(size_t size)
{
    N00B_INTERPOSE_BUMP();

    if (!runtime_ready()) {
        ensure_reals();
        if (real_valloc) {
            return real_valloc(size);
        }
    }
    size_t page = n00b_page_size ? n00b_page_size : 4096;
    return aligned_from_pool(page, size);
}

void *
n00b_interposed_pvalloc(size_t size)
{
    N00B_INTERPOSE_BUMP();

    if (!runtime_ready()) {
        ensure_reals();
        if (real_pvalloc) {
            return real_pvalloc(size);
        }
    }
    size_t page    = n00b_page_size ? n00b_page_size : 4096;
    size_t rounded = 0;
    if (__builtin_add_overflow(size, page - 1, &rounded)) {
        return nullptr;
    }
    rounded &= ~(page - 1);
    return aligned_from_pool(page, rounded);
}

#endif

// ============================================================================
// Install mechanism.
//
//   * Vendored QUIC libs (picoquic / picotls) + n00b's own QUIC glue are
//     redirected at COMPILE time: their build force-includes
//     <core/alloc_interpose_shim.h>, which #defines the libc malloc family to
//     the n00b_interposed_* entry points. That is the portable mechanism that
//     actually fixes the off-libc-worker trap (macOS dyld __interpose tables
//     only take effect from a dylib, never the main-exe image, so a
//     header/main-exe table cannot redirect statically-linked picoquic).
//   * Linux ALSO gets process-wide coverage via strong `malloc`/`free`/...
//     symbols in libn00b overriding libc's — this catches any other libc
//     malloc users too, not just the shimmed TUs.
//   * Windows: IAT hooking is not yet implemented.
// ============================================================================

#if defined(__linux__)

// These DELIBERATELY lack the n00b_ prefix (§10.2): they must use the exact
// libc symbol names to override libc's weak definitions process-wide. That is
// the entire mechanism — there is no prefixed alternative.
void  *malloc(size_t size) { return n00b_interposed_malloc(size); }
void   free(void *ptr) { n00b_interposed_free(ptr); }
void  *calloc(size_t c, size_t n) { return n00b_interposed_calloc(c, n); }
void  *realloc(void *p, size_t n) { return n00b_interposed_realloc(p, n); }
void  *reallocarray(void *p, size_t c, size_t n) { return n00b_interposed_reallocarray(p, c, n); }
char  *strdup(const char *s) { return n00b_interposed_strdup(s); }
char  *strndup(const char *s, size_t n) { return n00b_interposed_strndup(s, n); }
int    posix_memalign(void **m, size_t a, size_t s) { return n00b_interposed_posix_memalign(m, a, s); }
void  *aligned_alloc(size_t a, size_t s) { return n00b_interposed_aligned_alloc(a, s); }
void  *memalign(size_t a, size_t s) { return n00b_interposed_memalign(a, s); }
void  *valloc(size_t s) { return n00b_interposed_valloc(s); }
void  *pvalloc(size_t s) { return n00b_interposed_pvalloc(s); }
size_t malloc_usable_size(void *p) { return n00b_interposed_malloc_usable_size(p); }

#endif

// ============================================================================
// Probe + require.
// ============================================================================

bool
n00b_alloc_interposition_active(void)
{
    static _Atomic int cached = -1;
    int                c      = atomic_load(&cached);
    if (c != -1) {
        return c != 0;
    }

    // Verify the interposed allocator itself is functional: an interposed
    // allocation must bump the hit counter and land in a n00b allocator. (The
    // wiring of the shim into picoquic/picotls is a build-time guarantee via
    // the force-included shim header; this checks the runtime half.)
    if (!runtime_ready()) {
        return false;
    }
    uint64_t before = n00b_alloc_interpose_hits();
    void    *p      = n00b_interposed_malloc(1);
    uint64_t after  = n00b_alloc_interpose_hits();
    bool     ok     = (after > before) && p != nullptr
                    && owned_by_interpose_allocation(p);
    n00b_interposed_free(p);

    atomic_store(&cached, ok ? 1 : 0);
    return ok;
}

void
n00b_require_alloc_interposition(n00b_string_t *subsystem)
{
    if (n00b_alloc_interposition_active()) {
        return;
    }

    n00b_string_t *name = subsystem ? subsystem : r"this subsystem";

    n00b_eprintf("«#» requires the n00b interposed allocator, but it is not "
                 "functional in this process (the n00b allocator is not routing "
                 "interposed allocations). The vendored QUIC libraries and "
                 "n00b's QUIC glue must be built with the force-included shim "
                 "core/alloc_interpose_shim.h (see the picoquic/picotls "
                 "c_args in meson.build).",
                 name);
#if defined(_WIN32)
    n00b_eprintf("On Windows, allocator interposition (IAT hooking) is not "
                 "yet implemented.");
#endif

    n00b_panic("«#»: allocator interposition is not active", name);
}
