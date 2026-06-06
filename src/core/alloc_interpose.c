// alloc_interpose.c — plain-C ABI shim (§11). This file (and its header
// include/core/alloc_interpose.h) is a libc-ABI boundary: it DEFINES the libc
// malloc family, so libc-shaped signatures (`char *strdup(const char *)`, the
// raw malloc/free prototypes) and direct use of leaf libc string routines are
// allowed HERE and only here. Internal libn00b code uses the n00b surface.
//
// libc malloc-family interposition routed through n00b's user pool.
//
// See include/core/alloc_interpose.h for the rationale and lifecycle, and
// include/n00b/alloc_interpose.h for the per-platform install mechanism.
//
// Design notes:
//   * Post-init allocations go through the normal n00b allocator API on
//     rt->user_pool, so each allocation is recorded in n00b's OOB metadata
//     (user_pool is external_metadata=true). We deliberately do NOT add our
//     own header — for an over-aligned allocation we return an interior,
//     aligned pointer and recover the allocation start at free/realloc time
//     by probing that existing metadata downward in N00B_ALIGN steps (the
//     first hit is the containing allocation's base; allocations never
//     overlap, so this is exact).
//   * Pre-init (before the runtime/user_pool exist) we delegate to the real
//     libc symbols, resolved via dlsym(RTLD_NEXT). Those run on the main
//     thread with a full TCB, so libc is safe there. A small static
//     bootstrap arena satisfies any malloc that occurs *during* the dlsym
//     resolution itself (the classic interposer reentrancy window).
//   * free()/realloc() classify a pointer by address: bootstrap arena →
//     no-op/copy; owned by user_pool → recover base + n00b_free; otherwise a
//     pre-init libc pointer → real libc free/realloc.
//   * memcpy/memset/strlen/strnlen are leaf libc routines (no allocation, no
//     TSD/pthread_self), so they are safe to call on off-libc workers; this
//     is the libc boundary, so using them here is intentional, not a stdlib
//     substitution.

#include <dlfcn.h>
#include <string.h>
#include <stdatomic.h>
#include <errno.h>

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

static _Atomic bool reals_ready = false;
static _Atomic bool reals_busy  = false;

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

    atomic_store(&reals_ready, true);
    atomic_store(&reals_busy, false);
}

// ============================================================================
// User-pool routing.
// ============================================================================

static inline bool
runtime_ready(void)
{
    return n00b_option_is_set(n00b_default_runtime)
        && atomic_load(&n00b_get_runtime()->startup_complete);
}

static inline n00b_allocator_t *
user_pool(void)
{
    return (n00b_allocator_t *)&n00b_get_runtime()->user_pool;
}

// True if `p` points anywhere inside a current user_pool allocation.
static inline bool
owned_by_user_pool(void *p)
{
    n00b_allocator_opt_t a = n00b_mem_get_allocator(p);
    return n00b_option_is_set(a) && n00b_option_get(a) == user_pool();
}

// Recover the allocation start for a pointer known to live inside the user
// pool, using n00b's existing OOB metadata. For a normal allocation the
// pointer IS the base (first probe hits). For an over-aligned allocation the
// base sits a few N00B_ALIGN steps below the returned aligned pointer.
// Backstop for the downward probe. For our own allocations the base is at
// most (requested alignment - N00B_ALIGN) below the returned pointer; a
// normal (non-over-aligned) allocation hits on the first probe. The cap only
// bounds the loop for a corrupt/foreign pointer that nonetheless resolves to
// a user_pool page. 64 KiB comfortably covers any realistic alignment request
// (page alignment and below) while keeping the worst case bounded.
#define N00B_INTERPOSE_MAX_ALIGN_PROBE (1 << 16)
static void *
recover_pool_base(void *p)
{
    uintptr_t addr = (uintptr_t)p;
    uintptr_t low  = (addr >= N00B_INTERPOSE_MAX_ALIGN_PROBE)
                       ? addr - N00B_INTERPOSE_MAX_ALIGN_PROBE
                       : 0;

    for (uintptr_t cand = addr; cand >= low; cand -= N00B_ALIGN) {
        n00b_alloc_info_t info = n00b_find_alloc_info((void *)cand);
        if (info.kind == n00b_alloc_oob) {
            // OOB metadata is keyed by the exact base, so a hit means
            // `cand` is an allocation start.
            return (void *)cand;
        }
        if (cand < N00B_ALIGN) {
            break;
        }
    }
    return nullptr;
}

// ============================================================================
// The interposed malloc family.
// ============================================================================

void *
n00b_interposed_malloc(size_t size)
{
    N00B_INTERPOSE_BUMP();

    if (runtime_ready()) {
        return n00b_alloc_size_with_opts(size ? size : 1, 1,
                                         N00B_ALLOC_OPTS(user_pool()));
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

    if (runtime_ready() && owned_by_user_pool(ptr)) {
        void *base = recover_pool_base(ptr);
        if (base) {
            n00b_free(base);
            return;
        }
        // Owned-but-unrecoverable: the pointer is inside a user_pool page but
        // no allocation base was found within the probe window. This is a
        // "should never happen" (corruption, or an alignment larger than the
        // probe backstop). Don't hand a pool pointer to libc (that WOULD
        // corrupt libc's heap); make the anomaly loud instead of leaking it
        // silently.
        n00b_panic("alloc_interpose: free of an unrecoverable user_pool "
                   "pointer «#»",
                   (int64_t)(uintptr_t)ptr);
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

    if (runtime_ready()) {
        // user_pool allocations are zero-filled.
        return n00b_alloc_size_with_opts(total ? total : 1, 1,
                                         N00B_ALLOC_OPTS(user_pool()));
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

    if (runtime_ready() && owned_by_user_pool(ptr)) {
        void *base = recover_pool_base(ptr);
        if (base) {
            size_t prefix = (size_t)((char *)ptr - (char *)base);
            size_t old    = n00b_pool_usable_size(base);
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
        n00b_panic("alloc_interpose: realloc of an unrecoverable user_pool "
                   "pointer «#»",
                   (int64_t)(uintptr_t)ptr);
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

// Over-aligned allocation: the user pool guarantees only N00B_ALIGN (32-byte)
// alignment, so for a larger request we over-allocate by (align - N00B_ALIGN)
// and return the aligned pointer inside the allocation. No header is added —
// free/realloc/usable_size recover the base from n00b's metadata.
static void *
aligned_from_pool(size_t align, size_t size)
{
    if (!runtime_ready()) {
        ensure_reals();
        // Pre-init aligned allocation on the main thread: use the real one.
        void *p = nullptr;
        if (real_malloc) {
            // posix_memalign/aligned_alloc are rare pre-init; fall back to a
            // generously-aligned bump via the real allocator.
            (void)align;
            p = real_malloc(size);
        }
        return p;
    }

    size_t request = size ? size : 1;
    if (align > N00B_ALIGN) {
        request += (align - N00B_ALIGN);
    }

    void *base = n00b_alloc_size_with_opts(request, 1,
                                           N00B_ALLOC_OPTS(user_pool()));
    if (base == nullptr) {
        return nullptr;
    }

    uintptr_t aligned = ((uintptr_t)base + (align - 1)) & ~(uintptr_t)(align - 1);
    return (void *)aligned;
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
    if (runtime_ready() && owned_by_user_pool(ptr)) {
        void *base = recover_pool_base(ptr);
        if (base) {
            size_t prefix = (size_t)((char *)ptr - (char *)base);
            size_t usable = n00b_pool_usable_size(base);
            return usable > prefix ? usable - prefix : 0;
        }
    }
    return 0;
}

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
    // allocation must bump the hit counter and land in the user pool. (The
    // wiring of the shim into picoquic/picotls is a build-time guarantee via
    // the force-included shim header; this checks the runtime half.)
    if (!runtime_ready()) {
        return false;
    }
    uint64_t before = n00b_alloc_interpose_hits();
    void    *p      = n00b_interposed_malloc(1);
    uint64_t after  = n00b_alloc_interpose_hits();
    bool     ok     = (after > before) && p != nullptr && owned_by_user_pool(p);
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
                 "functional in this process (the user pool is not routing "
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
