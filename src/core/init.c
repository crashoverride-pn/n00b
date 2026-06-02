#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#ifndef _WIN32
#include <unistd.h>
#include <termios.h>
#include <sys/resource.h>
#else
#include "core/platform.h"
#endif

#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "adt/array.h"
#include "adt/option.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/crash.h"
#include "core/mmaps.h"
#include "core/alloc.h"
#include "core/arena.h"
#include "core/random.h"
#include "core/stw.h"
#include "core/gc.h"
#include "core/type_info.h"
#include "text/strings/style_registry.h"
#include "text/strings/theme.h"
#include "text/unicode/ctx.h"
#include "text/regex/ctx.h"
#include "core/string.h"
#include "core/buffer.h"
#include "conduit/conduit.h"
#include "conduit/service.h"
#include "conduit/fd_managed.h"
#include "conduit/fd_writer.h"
#include "conduit/io.h"
#include "parsers/tokenizer_registry.h"
#include "display/render/backend_registry.h"

size_t   n00b_page_size = 0;
uint64_t n00b_gc_guard  = 0;

extern void n00b_mmaps_initialize(n00b_mmap_ctx_t *ctx);

typedef n00b_option_t(n00b_runtime_t *) opt_rt_t;
opt_rt_t n00b_default_runtime = n00b_option_none(n00b_runtime_t *);

extern char **environ;

static inline void
setup_envp(n00b_runtime_t *rt, char *envp[])
{
    /* When the caller didn't pass envp explicitly, inherit the
     * libc-visible environment so n00b_getenv() observes the same
     * process state libc getenv() does. */
    if (envp == nullptr) {
        envp = environ;
    }
    if (envp == nullptr) {
        rt->envp     = n00b_array_checked_ptr(char *, 0, nullptr);
        rt->envp.len = 0;
        return;
    }

    int i = 0;
    while (envp[i] != nullptr) {
        i++;
    }
    rt->envp     = n00b_array_checked_ptr(char *, i, envp);
    rt->envp.len = i;
    environ      = envp;
}

#ifdef _WIN32
static inline void
setup_fd_limit(n00b_runtime_t *rt, int fd_limit)
{
    (void)rt;
    (void)fd_limit;
}
#else
static inline void
setup_fd_limit(n00b_runtime_t *rt, rlim_t fd_limit)
{
    struct rlimit limits;

    if (fd_limit < 0) {
        return;
    }

    if (getrlimit(RLIMIT_NOFILE, &limits)) {
        perror(__func__);
        exit(1);
    }

    if (!fd_limit || ((size_t)fd_limit) > limits.rlim_max) {
        fd_limit = limits.rlim_max;
    }
    limits.rlim_cur = fd_limit;

    if (setrlimit(RLIMIT_NOFILE, &limits)) {
        perror(__func__);
        exit(1);
    }
}
#endif

static inline void
setup_threads(n00b_runtime_t *rt, unsigned int max_threads)
{
    if (max_threads == 0) {
        max_threads = N00B_THREADS_MAX;
    }
    rt->max_threads = (uint32_t)max_threads;
    /* Allocate from system_pool (hidden from GC, non-moving) so other
     * threads can safely read slot state without STW coordination. */
    n00b_allocator_t *rpool = (n00b_allocator_t *)&rt->system_pool;
    rt->threads = n00b_alloc_array_with_opts(
        n00b_thread_record_t, (int64_t)max_threads,
        &(n00b_alloc_opts_t){.allocator = rpool});
    /* Zero-initialize all slots — the field is "fresh" by default. */
    memset(rt->threads, 0,
           sizeof(n00b_thread_record_t) * (size_t)max_threads);

    /* Live-slot bitmap for n00b_thread_self()'s foreign-safe bounds scan
     * (see runtime.h).  One bit per slot, from system_pool, zeroed.  Must
     * exist before n00b_thread_init below so the main thread can set its
     * bit. */
    uint64_t nwords    = ((uint64_t)max_threads + 63u) / 64u;
    rt->live_slot_bits = n00b_alloc_array_with_opts(
        _Atomic uint64_t, (int64_t)nwords,
        &(n00b_alloc_opts_t){.allocator = rpool, .no_scan = true});
    memset(rt->live_slot_bits, 0, sizeof(uint64_t) * (size_t)nwords);

    /* Callstack-region base set for n00b_thread_self()'s O(1) worker fast
     * path (see runtime.h).  Power-of-two sized at >= 4x max_threads so the
     * load factor stays low (~1 probe); from system_pool, zeroed. */
    uint64_t set_sz = 256;
    while (set_sz < 4ull * (uint64_t)max_threads) {
        set_sz <<= 1;
    }
    rt->callstack_base_set_mask = (uint32_t)(set_sz - 1);
    rt->callstack_base_set      = n00b_alloc_array_with_opts(
        _Atomic(uintptr_t), (int64_t)set_sz,
        &(n00b_alloc_opts_t){.allocator = rpool, .no_scan = true});
    memset(rt->callstack_base_set, 0, sizeof(uintptr_t) * (size_t)set_sz);

    rt->next_thread_slot = 0;
    n00b_thread_init(.runtime = rt);
}

static void *
n00b_slab_alloc(n00b_allocator_t *self, uint32_t sz, void *ignore)
{
    auto r = n00b_mmap(sz, .allocator = self);
    assert(n00b_result_is_ok(r));
    return n00b_result_get(r);
}

void
n00b_slab_free(n00b_allocator_t *self, void *ptr)
{
    (void)n00b_munmap(ptr);
}

static inline void
setup_slab_allocator(n00b_runtime_t *rt)
{
    n00b_allocator_setup((n00b_allocator_t *)&rt->slab_allocator,
                         (n00b_calloc_fn)n00b_slab_alloc,
                         .free              = (n00b_free_fn)n00b_slab_free,
                         .name              = "slab_allocator",
                         .inline_headers    = false,
                         .external_metadata = false,
                         .hidden            = true,
                         .__system          = true);
}

void
n00b_shutdown(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    if (!rt) return;

    /* Signal any blocking futex waiters to break out — they'll see
     * `shutdown_started == true` and return false instead of
     * looping while the thread they're waiting on is being reaped. */
    n00b_atomic_store(&rt->shutdown_started, true);

    /* Drain the per-runtime HTTP connection pool before tearing
     * down the conduit (close-fns may release fds that the conduit
     * tracks). */
    n00b_http_connection_pool_t *pool =
        n00b_atomic_load(&rt->http_connection_pool);
    if (pool) {
        extern void
            n00b_http_connection_pool_close(n00b_http_connection_pool_t *);
        n00b_http_connection_pool_close(pool);
    }

    n00b_conduit_t *c = rt->default_conduit;
    if (c) {
        n00b_conduit_destroy(c);
    }

    n00b_stop_the_world();
    n00b_restart_the_world();

    while (n00b_atomic_load(&rt->live_threads) > 1) {
        n00b_futex_wait((n00b_futex_t *)&rt->live_threads,
                         n00b_atomic_load(&rt->live_threads),
                         50000000);
    }

    // Drain any remaining output on tty file descriptors.
#ifndef _WIN32
    if (isatty(STDOUT_FILENO)) {
        tcdrain(STDOUT_FILENO);
    }
    if (isatty(STDERR_FILENO)) {
        tcdrain(STDERR_FILENO);
    }
#endif
}

void
n00b_exit(int code)
{
    n00b_shutdown();
    exit(code);
}

// The runtime is a process singleton, brought up in two phases.
// `n00b_early_init` stands up just the memory subsystem (page size, the
// mmap registry, the system / runtime-object pools, and the core runtime
// lists) so that arenas and n00b lists are usable from
// `[[gnu::constructor]]` context — in particular the per-TU GC-root and
// `@rpc` registrars that fire before `main`.  `n00b_init` then completes
// the runtime (threads, the GC heap, the type registry, conduit IO, ...).
// Both are idempotent; `n00b_early_init` runs from a high-priority ctor
// AND defensively from `n00b_init` (some static-link / embedding modes do
// not run constructors).
// [[n00b::nomap]]: exempt the singleton from the auto-GC-roots transform.
// Its pointer members (incl. the pools' _Atomic free-list heads) must not
// be auto-registered as roots; n00b_init registers the GC-relevant
// sub-objects explicitly, matching the pre-singleton behavior.
[[n00b::nomap]] static n00b_runtime_t n00b_the_runtime;
static _Atomic bool                   n00b_early_init_done = false;

void
n00b_early_init(void)
{
    if (atomic_exchange(&n00b_early_init_done, true)) {
        return;
    }

    n00b_runtime_t *rt = &n00b_the_runtime;

#ifdef _WIN32
    n00b_page_size = base_page_size();
#else
    n00b_page_size = sysconf(_SC_PAGESIZE);
#endif

    if (!n00b_gc_guard) {
        n00b_gc_guard = n00b_rand64();
    }

    *rt = (n00b_runtime_t){
        .stw            = N00B_NO_OWNER,
        .stw_generation = 0,
        .stw_nesting    = 0,
    };

    // Publish the runtime before the first arena/pool allocation:
    // n00b_mmap / n00b_get_runtime resolve the mmap registry through
    // n00b_default_runtime.
    if (!n00b_option_is_set(n00b_default_runtime)) {
        n00b_default_runtime = n00b_option_set(n00b_runtime_t *, rt);
    }

    setup_slab_allocator(rt);
    n00b_mmaps_initialize(&rt->mmaps);

    // system_pool: hidden, no-STW; backs the root list / lock records so
    // the collector and other threads can read them without coordination.
    n00b_pool_init(&rt->system_pool,
                   .__system = true,
                   .hidden   = true,
                   .name     = "system_pool");

    // runtime_obj_pool: GC-visible, non-moving, external_metadata (see the
    // long note in n00b_init's history / runtime.h for the D-034 rationale).
    n00b_pool_init(&rt->runtime_obj_pool,
                   .hidden            = false,
                   .external_metadata = true,
                   .name              = "runtime_obj_pool");

    // conduit_pool: hidden from GC. Stood up here (not just in n00b_init)
    // so the @rpc registrars, which fire as [[gnu::constructor]]s and
    // allocate their registry entries from conduit_pool (n00b_rpc_alloc),
    // can register directly at ctor time without a defer queue.
    n00b_pool_init(&rt->conduit_pool,
                   .hidden = true,
                   .name   = "conduit_pool");

    n00b_allocator_t *rpool = (n00b_allocator_t *)&rt->system_pool;
    rt->gc_roots            = n00b_list_new(n00b_gc_root_t, rpool);
    rt->finalizers          = n00b_list_new_private(n00b_finalizer_info_t *, rpool);
    rt->scannable_pools     = n00b_list_new(n00b_allocator_t *, rpool);
    /* See runtime.h: every external_metadata pool registers here so
     * the GC mark phase can walk per-alloc metadata directly. */
    rt->metadata_pools      = n00b_list_new(n00b_allocator_t *, rpool);
    n00b_atomic_store(&rt->gc_current_epoch, 0);
    n00b_atomic_store(&rt->debug_leak_detect, false);
}

// Highest user constructor priority (101) so the memory subsystem is up
// before any other [[gnu::constructor]] in the image runs — notably the
// per-TU GC-root / @rpc registrars.
[[gnu::constructor(101)]] static void
n00b_early_init_ctor(void)
{
    n00b_early_init();
}

void
n00b_init(n00b_runtime_t *rt, int argc, char *argv[]) _kargs
{
    n00b_allocator_t *allocator       = nullptr;
    char             **envp           = nullptr;
    char              *numeric_locale = "";
    int                fd_limit       = 0;
    unsigned int       max_threads    = N00B_THREADS_MAX;
}
{
    static _Atomic bool n00b_init_called = false;
    if (atomic_exchange(&n00b_init_called, true)) {
        return;
    }

    // Stand up the memory subsystem if a [[gnu::constructor]] hasn't
    // already (idempotent — covers static-link / embedding modes that
    // don't run constructors).
    n00b_early_init();

    // The runtime is the singleton owned by n00b_early_init; the `rt`
    // parameter is vestigial (TODO: remove with the allocator migration —
    // see MALLOC_AUDIT.md follow-ups).
    (void)rt;
    rt = &n00b_the_runtime;

    if (numeric_locale) {
        setlocale(LC_NUMERIC, numeric_locale);
    }
    rt->argv = n00b_array_checked_ptr(char *, argc, argv);
    setup_envp(rt, envp);
    setup_fd_limit(rt, fd_limit);

    // (page size, mmap registry, system / runtime-object pools, and the
    // core runtime lists were stood up by n00b_early_init above. GC-root
    // and @rpc registrars self-bootstrap via n00b_early_init and register
    // directly, so there is no longer a pre-init defer queue to flush.)

    setup_threads(rt, max_threads);

    if (allocator) {
        rt->default_allocator = allocator;
        rt->default_arena     = nullptr;
    }
    else {
        rt->default_arena     = n00b_new_arena(.use_gc = true,
                                                .name   = "default");
        rt->default_allocator = (n00b_allocator_t *)rt->default_arena;
    }

    n00b_type_registry_init();

    // (conduit_pool was stood up in n00b_early_init — hidden from GC,
    // external_metadata OFF for the hot path — so @rpc registrars can
    // allocate from it at ctor time.)

    // Application-level "user_pool": hidden + non-GC like
    // conduit_pool, but with external_metadata so each alloc gets
    // an OOB record (alive bit + gc_epoch + callsite file_name).
    // Application code that opts in by allocating here is then
    // visible to n00b_debug_find_leaks — handy for leak hunts on
    // long-running daemons.  Not for hot-path traffic; reach for
    // conduit_pool or system_pool there.
    n00b_pool_init(&rt->user_pool,
                   .hidden            = true,
                   .external_metadata = true,
                   .name              = "user_pool");

    rt->sub_map = n00b_alloc(n00b_dict_untyped_t);
    n00b_dict_untyped_init(rt->sub_map,
                           .skip_obj_hash = true);
    n00b_gc_register_root(rt->sub_map);

    // Unicode subsystem: bundle of per-property range tables / by-name
    // caches / segmentation tables.  Allocated eagerly so accessors
    // can deref unconditionally; per-subsystem tables are still lazy
    // (each `*_ensure_init` builds its own slice array on first use).
    rt->unicode_ctx = n00b_alloc(n00b_unicode_ctx_t);
    n00b_gc_register_root(rt->unicode_ctx);

    // Regex subsystem: port-side caches (named pairset interning,
    // precomputed \w table, case-fold equivalence index).
    rt->regex_ctx = n00b_alloc(n00b_regex_ctx_t);
    n00b_gc_register_root(rt->regex_ctx);

    n00b_gc_register_root(rt->type_registry);
    n00b_gc_register_root(rt->default_conduit);
    n00b_gc_register_root(rt->default_service);
    n00b_gc_register_root(rt->stdin_owner);
    n00b_gc_register_root(rt->stdout_owner);
    n00b_gc_register_root(rt->stderr_owner);
    n00b_gc_register_root(rt->stdout_topic);
    n00b_gc_register_root(rt->stderr_topic);

    n00b_str_registry_init();
    n00b_theme_init();
    n00b_tokenizers_init();
    n00b_renderer_registry_init();
    rt->theme_name = "n00b-classic";

    // Create default conduit + service for IO (stdout/stderr, signals).
    n00b_result_t(n00b_conduit_t *) cond_r = n00b_conduit_new();
    if (n00b_result_is_ok(cond_r)) {
        rt->default_conduit = n00b_result_get(cond_r);

        n00b_result_t(n00b_conduit_service_t *) svc_r =
            n00b_conduit_service_new(rt->default_conduit);

        if (n00b_result_is_ok(svc_r)) {
            rt->default_service = n00b_result_get(svc_r);
            n00b_conduit_service_start(rt->default_service);

            // Get the default IO thread's backend for fd management.
            auto io_opt = n00b_conduit_service_default_io(rt->default_service);

            if (n00b_option_is_set(io_opt)) {
                n00b_conduit_svc_thread_t *svc_thread = n00b_option_get(io_opt);

                // Managed fd 0 (stdin). Reads stay quiescent until the
                // first subscriber attaches to owner->read_topic — see
                // n00b_conduit_fd_manage / on_first_subscribe. Owning
                // fd 0 here means n00b_stdin() can hand a ready-to-use
                // owner to consumers without each one repeating the
                // manage-fd dance.
                auto in_r = n00b_conduit_fd_manage(
                    rt->default_conduit, svc_thread->io, 0, false);
                if (n00b_result_is_ok(in_r)) {
                    rt->stdin_owner = n00b_result_get(in_r);
                }

                auto out_r = n00b_conduit_fd_manage(
                    rt->default_conduit, svc_thread->io, 1, false);
                if (n00b_result_is_ok(out_r)) {
                    rt->stdout_owner = n00b_result_get(out_r);
                }

                auto err_r = n00b_conduit_fd_manage(
                    rt->default_conduit, svc_thread->io, 2, false);
                if (n00b_result_is_ok(err_r)) {
                    rt->stderr_owner = n00b_result_get(err_r);
                }
            }

            // Create typed stdout/stderr buffer topics and wire
            // fd-writer sinks that do the actual kernel write().
            auto *out_typed = n00b_conduit_topic_init(
                n00b_buffer_t *,
                rt->default_conduit,
                n00b_conduit_str_uri(r"stdout"));

            if (out_typed) {
                rt->stdout_topic = (n00b_conduit_topic_base_t *)out_typed;
                n00b_conduit_fd_writer_new(rt->default_conduit,
                                            out_typed, 1);
            }

            auto *err_typed = n00b_conduit_topic_init(
                n00b_buffer_t *,
                rt->default_conduit,
                n00b_conduit_str_uri(r"stderr"));

            if (err_typed) {
                rt->stderr_topic = (n00b_conduit_topic_base_t *)err_typed;
                n00b_conduit_fd_writer_new(rt->default_conduit,
                                            err_typed, 2);
            }
        }
    }

    n00b_crash_init(); // WP-3b (D-039)
    n00b_stw_init();   // WP-4 (D-040) — preemptive-STW suspend mechanism

    rt->startup_complete = true;
}

void
n00b_init_simple(int argc, char *argv[])
{
    // The runtime is the process singleton owned by n00b_early_init /
    // n00b_init; the rt argument is vestigial (see MALLOC_AUDIT.md
    // follow-up to remove it).
    n00b_init(nullptr, argc, argv);
}
