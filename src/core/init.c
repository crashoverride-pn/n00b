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
n00b_shutdown() _kargs
{
    n00b_runtime_t *runtime = nullptr; // nullptr = use n00b_get_runtime()
}
{
    /* The runtime defaults to the active default runtime; callers that
     * hold an explicit handle (e.g. the CLI pattern, whose runtime is a
     * still-live stack local at the call site) may pass `.runtime` to
     * avoid relying on the global. */
    n00b_runtime_t *rt = (runtime != nullptr) ? runtime : n00b_get_runtime();
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

    /* Migrate the main OS thread's exact-GC-frame chain back onto the
     * bootstrap thread, then drop the runtime handle.  n00b_thread_init
     * carried the pre-init bootstrap chain ONTO the registered main
     * thread (thread.c: init_self.gc_stack_top = _n00b_bootstrap_thread
     * .gc_stack_top); this is the symmetric reverse at teardown.  Once
     * n00b_default_runtime is cleared, n00b_thread_self() resolves to
     * &_n00b_bootstrap_thread via its `!runtime` guard, so the ncc
     * auto-gc-roots epilogues (gc_stack_pop -> n00b_thread_self) that
     * run in callers AFTER n00b_shutdown() returns (a) no longer
     * dereference the now-dead runtime — in the CLI pattern a returned
     * stack-local n00b_runtime_t, otherwise EXC_BAD_ACCESS — and (b)
     * find their frames on the bootstrap chain, keeping gc_stack_pop's
     * frame-chain invariant (gc.c assert) intact for BOTH the
     * init-at-top and init-mid-call-tree patterns. */
    n00b_thread_t *self = n00b_thread_self();
    if (self != nullptr) {
        _n00b_bootstrap_thread.gc_stack_top    = self->gc_stack_top;
        _n00b_bootstrap_thread.gc_stack_policy = self->gc_stack_policy;
    }
    n00b_default_runtime = n00b_option_none(n00b_runtime_t *);
}

void
n00b_exit(int code)
{
    n00b_shutdown();
    exit(code);
}

/* Plain-C entry point for code not compiled through ncc (the AOT
 * startup shim emitted by the n00b compiler, compiled with clang;
 * see src/tools/n00b.c).  Mirrors n00b_init_simple: such callers
 * cannot expand the _kargs form, so they call this, which shuts down
 * the default runtime. */
void
n00b_shutdown_simple(void)
{
    n00b_shutdown();
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

#ifdef _WIN32
    n00b_page_size = base_page_size();
#else
    n00b_page_size = sysconf(_SC_PAGESIZE);
#endif

    if (!n00b_gc_guard) {
        n00b_gc_guard = n00b_rand64();
    }

    assert(rt);
    *rt = (n00b_runtime_t){};

    // Pure-preemptive STW lock (WP-001): the single reader/writer gate.
    // Critical execution takes a READ lock; the collector takes the WRITE lock.
    // Initialize WITHOUT n00b_rw_init: its n00b_lock_init_accounting runs a
    // trailing n00b_find_alloc_info probe that touches GC allocators not yet up
    // here, and this gate is taken during thread init/destroy before they are.
    // The runtime struct was just zeroed (*rt = {}) — futex unlocked, rwdebug
    // list empty — so we only stamp owner=N00B_NO_OWNER (so the first real
    // acquire is not mistaken for tid-0 ownership), the lock type, and the
    // accounting opt-outs (no_log / inited).
    n00b_futex_init(&rt->critical_execution.futex);
    n00b_core_lock_info_t ce_info = {
        .owner    = N00B_NO_OWNER,
        .type     = N00B_NLT_RW,
        .nesting  = 0,
        .reserved = 0,
    };
    n00b_atomic_store(&rt->critical_execution.data, ce_info);
    rt->critical_execution.inited       = true;
    rt->critical_execution.no_log       = true;
    rt->critical_execution.creation_loc = N00B_LOC_STRING();
    n00b_atomic_store(&rt->stw_active, false);

    if (!n00b_option_is_set(n00b_default_runtime)) {
        n00b_default_runtime = n00b_option_set(n00b_runtime_t *, rt);
    }

    if (numeric_locale) {
        setlocale(LC_NUMERIC, numeric_locale);
    }
    rt->argv = n00b_array_checked_ptr(char *, argc, argv);
    setup_envp(rt, envp);
    setup_fd_limit(rt, fd_limit);

    setup_slab_allocator(rt);
    n00b_mmaps_initialize(&rt->mmaps);

    // Initialize the system pool.  This is a system-level allocator
    // (hidden from GC, no STW checks) used to back the root list and
    // lock accounting records so that the collector and other threads
    // can read them safely.
    n00b_pool_init(&rt->system_pool,
                   .__system = true,
                   .hidden   = true,
                   .name     = "system_pool");

    // GC-VISIBLE, non-moving `runtime_obj_pool` (WP-3a / D-034).  Holds
    // GC-reclaimable runtime structs (currently `n00b_thread_t`).  Named
    // distinctly from the upstream `user_pool` (initialized below — a HIDDEN
    // leak-tracking pool; the two are NOT the same — WP-close deconfliction,
    // D-034/D-039).  Initialized with `hidden = false` and WITHOUT `.__system`
    // so the GC treats its allocations as ordinary objects: reachable -> kept,
    // unreferenced -> collected.  Being a pool it is non-moving, so the raw
    // `rt->threads[].thread` pointers and `n00b_thread_self()` stay valid
    // across collections.
    //
    // No `rt->scannable_pools` registration is performed here: in this
    // branch nothing consumes that list (neither `n00b_pool_init` /
    // `n00b_allocator_setup` nor any `gc.c` scan path reads it), and the
    // thread struct is already reached by the explicit thread-struct /
    // record / lock-chain scan in `n00b_scan_thread_stacks`.  The
    // GC-collects-unreferenced-pool-allocations capability (which would
    // consume `scannable_pools`) is in an unmerged PR (D-034); until it
    // lands, the struct is no longer bulk-freed (it left `system_pool`)
    // but is not yet GC-reclaimed -- a known, tracked leak that closes at
    // that merge.  Deconfliction with the PR happens at WP-close rebase.
    // external_metadata=true is REQUIRED post-WP-032: pool.c registers a pool's
    // pages in the global mmap tree (so n00b_mem_get_allocator can attribute an
    // allocation back to its pool — the D-034 foundation) ONLY for non-__system
    // pools with external_metadata.  It also supplies the per-alloc liveness
    // metadata (alive bit + gc_epoch) the eventual GC-collects-runtime_obj_pool
    // capability needs (D-034).  Stays hidden=false (GC-visible) and non-moving.
    n00b_pool_init(&rt->runtime_obj_pool,
                   .hidden            = false,
                   .external_metadata = true,
                   .name              = "runtime_obj_pool");

    n00b_allocator_t *rpool = (n00b_allocator_t *)&rt->system_pool;
    rt->gc_roots            = n00b_list_new(n00b_gc_root_t, .allocator = rpool);
    rt->finalizers          = n00b_list_new_private(n00b_finalizer_info_t *, .allocator = rpool);
    rt->scannable_pools     = n00b_list_new(n00b_allocator_t *, .allocator = rpool);
    /* See runtime.h: every external_metadata pool registers here so
     * the GC mark phase can walk per-alloc metadata directly. */
    rt->metadata_pools      = n00b_list_new(n00b_allocator_t *, .allocator = rpool);
    n00b_atomic_store(&rt->gc_current_epoch, 0);
    n00b_atomic_store(&rt->debug_leak_detect, false);

    // Flush any GC root registrations parked by `n00b_gc_register_roots`
    // during dynamic loader `[[gnu::constructor]]` phase (WP-003 / D-036,
    // F-4). Must happen after `rt->gc_roots` exists AND
    // `n00b_default_runtime` is set (the latter happened above).
    // Constructor-phase entries land first; subsequent
    // `n00b_gc_register_roots` calls bypass the defer queue.
    _n00b_gc_flush_deferred_roots();

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

    // Conduit infrastructure pool: hidden from GC so the copying
    // collector never scans or relocates conduit objects.  Objects
    // that need GC tracing are registered as roots explicitly.
    //
    // external_metadata is deliberately OFF here: the hot path
    // does many allocs/frees per second, and per-alloc OOB+dict
    // bookkeeping is unaffordable at that rate. Opt back in only
    // when a leak hunt requires it.
    n00b_pool_init(&rt->conduit_pool,
                   .hidden = true,
                   .name   = "conduit_pool");

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

    // Install the crash (WP-3b/D-039) and preemptive-STW suspend (WP-4/D-040)
    // signal handlers BEFORE starting the conduit service, because that service
    // spawns the IO worker thread (n00b_conduit_service_start, below).  A thread
    // must never exist before these are installed: otherwise a fault in the new
    // worker dies silently with no handler, and (on Linux) the worker would be
    // un-suspendable until the RT-signal handler appeared.  Both only need the
    // allocator + mmap machinery, which are up by here.  (CLONE_SIGHAND means a
    // later-installed disposition would eventually reach the worker, but the
    // creation/early-run window must be covered up front.)
    n00b_crash_init(); // WP-3b (D-039)
    n00b_stw_init();   // WP-4 (D-040) — preemptive-STW suspend mechanism

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

    rt->startup_complete = true;
}

void
n00b_init_simple(int argc, char *argv[])
{
    static n00b_runtime_t *rt = nullptr;

    if (!rt) {
        rt = calloc(1, sizeof(n00b_runtime_t));
    }

    n00b_init(rt, argc, argv);
}
