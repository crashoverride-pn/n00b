#include <stdio.h>
#include <assert.h>
#include <signal.h>   // sigaltstack / stack_t (Phase 2 probe)
#if !defined(_WIN32)
#include <stdlib.h>   // mkstemp
#include <unistd.h>   // fork / execv / _exit (Phase 3/4 fork+exec harness)
#include <sys/wait.h> // waitpid / WIFEXITED / WEXITSTATUS
#include <string.h>   // strncmp / strstr (crash-child flag dispatch)
#endif

#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/callstack.h"
#include "core/crash.h"
#include "core/crash_capture.h"
#include "core/mmaps.h"
#include "util/marshal.h"  // n00b_marshal / n00b_unmarshal (marshal roundtrip)
#include "core/buffer.h"   // n00b_buffer_t
#include "core/align.h"
#include "core/stw.h"

// ============================================================================
// WP-3b crash detection / guard-page stack-overflow handler.
//
// Phases 1+2 (guard-band classification substrate; per-worker sigaltstack) run
// in the test process.  Phases 3+4 (the SIGSEGV/SIGBUS handler, fault
// classification, crash_handler delivery, abort-after-handler) each FAULT and
// abort the process, so they run in an isolated child launched by fork+EXEC of
// this same binary with a `--crash-child=` flag.  fork+exec (NOT fork+reinit)
// gives the child a pristine process image, avoiding the fork-with-threads
// hazard of re-initializing n00b in a forked child.  The outcome is encoded in
// the child's exit code:
//   140 = the registered user crash_handler ran (it _exit(140)s)
//   139 = the global handler ran with NO user handler, then returned under
//         SA_RESETHAND so the OS default SIGSEGV path terminated the child
//    42 = the worker never faulted (sentinel: the test would fail)
//    43 = exec failed (parent side)
// ============================================================================

// --- Phase 1: guard-band classification substrate -------------------------

typedef struct {
    _Atomic(void *) guard_lo;
    _Atomic(void *) guard_hi;
    _Atomic(int)    checks;
    _Atomic(int)    perms;
} guard_probe_t;

static void *
guard_probe_worker(void *arg)
{
    guard_probe_t *p    = arg;
    n00b_thread_t *self = n00b_thread_self();

    void *lo = n00b_atomic_load(&self->guard_lo);
    void *hi = n00b_atomic_load(&self->guard_hi);
    atomic_store(&p->guard_lo, lo);
    atomic_store(&p->guard_hi, hi);

    int checks = 0;
    if (lo != nullptr && hi != nullptr) {
        checks |= 1;
    }
    if (lo != nullptr
        && ((uint64_t)hi - (uint64_t)lo)
               == (N00B_CALLSTACK_GUARD_PAGES * (uint64_t)n00b_page_size)) {
        checks |= 2;
    }
    if (lo != nullptr && ((uint64_t)lo % (uint64_t)n00b_page_size) == 0) {
        checks |= 4;
    }
    if (lo != nullptr) {
        n00b_option_t(n00b_mmap_info_t *) m = n00b_mmap_by_address(lo);
        if (n00b_option_is_set(m)) {
            n00b_mmap_info_t *info = n00b_option_get(m);
            atomic_store(&p->perms, (int)info->perms);
            if (info->perms == n00b_mmap_perms_no_access) {
                checks |= 8;
            }
        }
    }

    atomic_store(&p->checks, checks);
    return nullptr;
}

static void
test_guard_range_cached(void)
{
    guard_probe_t p = {};

    n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(guard_probe_worker, &p);
    assert(n00b_result_is_ok(r));
    n00b_thread_join(n00b_result_get(r));

    int checks = atomic_load(&p.checks);
    assert(checks & 1);
    assert(checks & 2);
    assert(checks & 4);
    assert(checks & 8);

    printf("  [PASS] guard_range_cached (lo=%p hi=%p span=%llu page=%llu perms=%d)\n",
           atomic_load(&p.guard_lo),
           atomic_load(&p.guard_hi),
           (unsigned long long)((uint64_t)atomic_load(&p.guard_hi)
                                - (uint64_t)atomic_load(&p.guard_lo)),
           (unsigned long long)n00b_page_size,
           atomic_load(&p.perms));
}

// --- Phase 2: per-worker alternate signal stack ---------------------------

typedef struct {
    _Atomic(void *) ss_sp;
    _Atomic(size_t) ss_size;
    _Atomic(int)    installed;
} altstack_probe_t;

static void *
altstack_probe_worker(void *arg)
{
    altstack_probe_t *p   = arg;
    stack_t           old = {};
    if (sigaltstack(nullptr, &old) == 0) {
        atomic_store(&p->ss_sp, old.ss_sp);
        atomic_store(&p->ss_size, old.ss_size);
        atomic_store(&p->installed, (old.ss_flags & SS_DISABLE) ? 0 : 1);
    }
    return nullptr;
}

static void
test_altstack_installed_per_worker(void)
{
    altstack_probe_t p = {};

    n00b_result_t(n00b_thread_t *) r = n00b_thread_spawn(altstack_probe_worker,
                                                         &p);
    assert(n00b_result_is_ok(r));
    n00b_thread_join(n00b_result_get(r));

    assert(atomic_load(&p.installed));            // live (not SS_DISABLE)
    assert(atomic_load(&p.ss_sp) != nullptr);     // has a stack pointer
    assert(atomic_load(&p.ss_size) >= (size_t)(64 * 1024)); // ample (it is an n00b callstack region's usable span)

    printf("  [PASS] altstack_installed_per_worker (sp=%p size=%zu)\n",
           atomic_load(&p.ss_sp),
           atomic_load(&p.ss_size));
}

// --- Phases 3+4: fault handler + delivery + abort-after-handler -----------

#if !defined(_WIN32)

// User crash handler: terminating here (140) proves the registered handler was
// invoked. Without a user handler, the runtime handler returns under
// SA_RESETHAND so the OS default SIGSEGV path terminates the process.
static void
exit140_handler(n00b_thread_t *t, void *d)
{
    (void)t;
    (void)d;
    _exit(140);
}

static volatile int n00b_crash_test_sink;

// Recurse with a real (volatile, used-after-call) frame so the compiler cannot
// tail-call-optimize it — grows the stack down into the PROT_NONE guard band.
static int
blow_stack(int depth)
{
    volatile char buf[1024];
    buf[0]  = (char)depth;
    int r   = blow_stack(depth + 1);
    n00b_crash_test_sink += buf[0] + r;
    return r;
}

static void *
overflow_worker(void *arg)
{
    (void)arg;
    return (void *)(intptr_t)blow_stack(0);
}

static void *
segv_worker(void *arg)
{
    (void)arg;
    volatile int *p = (volatile int *)(uintptr_t)0x8; // unmapped low address
    *p              = 1;
    return nullptr;
}

// Crash-child mode (this process was fork+exec'd with `--crash-child=WHICH`):
// init n00b fresh in this pristine process, spawn the faulting worker, and let
// the fault abort us.  WHICH selects the worker and whether a user handler is
// registered.  Returns only if no fault occurred (caller _exit(42)s).
static void
crash_child_run(const char *which, int argc, char **argv)
{
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);

    if (argc >= 3 && strncmp(argv[2], "--crash-log-fd=", 15) == 0) {
        int fd = 0;
        const char *p = argv[2] + 15;
        for (; *p >= '0' && *p <= '9'; p++) {
            fd = fd * 10 + (*p - '0');
        }
        n00b_crash_set_log_fd(fd);
    }

    void *(*worker)(void *) = (strstr(which, "overflow") != nullptr)
                                  ? overflow_worker
                                  : segv_worker;
    bool with_handler = (strstr(which, "nohandler") == nullptr);

    n00b_result_t(n00b_thread_t *) r;
    if (with_handler) {
        r = n00b_thread_spawn(worker,
                              nullptr,
                              .crash_handler      = exit140_handler,
                              .crash_handler_data = nullptr);
    }
    else {
        r = n00b_thread_spawn(worker, nullptr);
    }
    if (n00b_result_is_ok(r)) {
        n00b_thread_join(n00b_result_get(r)); // worker faults -> abort
    }
}

// Parent side: fork+exec this binary with the crash-child flag; return the
// child's exit code (or 128+signal if it died by a signal).
static int
run_crash_case_with_arg(const char *self, const char *flag, const char *extra)
{
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        // A registered user crash_handler is delivered only in crash-debug mode
        // (the production fatal-signal path deliberately skips arbitrary
        // callbacks so a wedged callback can't block launchd restart — see
        // _n00b_crash_handler). The *-handler variants verify that delivery, so
        // enable crash-debug for them; the nohandler variants intentionally
        // exercise the production raw-exit path (128+signal).
        if (strstr(flag, "nohandler") == nullptr) {
            setenv("N00B_CRASH_DEBUG", "1", 1);
        }
        if (extra != nullptr) {
            execl(self, self, flag, extra, (char *)nullptr);
        } else {
            execl(self, self, flag, (char *)nullptr);
        }
        _exit(43); // exec failed
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return WIFSIGNALED(status) ? (128 + WTERMSIG(status)) : -1;
}

static int
run_crash_case(const char *self, const char *flag)
{
    return run_crash_case_with_arg(self, flag, nullptr);
}

static void
test_crash_overflow_delivers(const char *self)
{
    int rc = run_crash_case(self, "--crash-child=overflow-handler");
    assert(rc == 140); // stack overflow -> handler -> user crash_handler -> abort
    printf("  [PASS] crash_overflow_delivers (rc=%d)\n", rc);
}

static void
test_crash_segv_delivers(const char *self)
{
    int rc = run_crash_case(self, "--crash-child=segv-handler");
    assert(rc == 140); // wild write -> handler -> user crash_handler -> abort
    printf("  [PASS] crash_segv_delivers (rc=%d)\n", rc);
}

static void
test_crash_no_handler_aborts(const char *self)
{
    int rc = run_crash_case(self, "--crash-child=segv-nohandler");
    assert(rc == 139); // fault, no user handler -> global handler -> OS default SIGSEGV
    printf("  [PASS] crash_no_handler_aborts (rc=%d)\n", rc);
}

static void
test_crash_log_fd_records(const char *self)
{
    char path[] = "/tmp/n00b-crash-log-XXXXXX";
    int  fd     = mkstemp(path);
    assert(fd >= 0);

    char arg[64];
    snprintf(arg, sizeof(arg), "--crash-log-fd=%d", fd);

    int rc = run_crash_case_with_arg(self,
                                     "--crash-child=segv-nohandler",
                                     arg);
    assert(rc == 139);

    assert(lseek(fd, 0, SEEK_SET) == 0);
    char    buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    assert(n > 0);
    buf[n] = '\0';
    assert(strstr(buf, "n00b: fatal: invalid memory access\n") != nullptr);

    close(fd);
    unlink(path);
    printf("  [PASS] crash_log_fd_records (rc=%d path=%s)\n", rc, path);
}

#endif // !_WIN32

// ===========================================================================
// Structured-capture API tests (the new crash_capture surface).  These run in
// the main process with no fault -- the manual capture path exercises the same
// scratch->copy-out mechanism as the signal path.
// ===========================================================================

// (a) n00b_backtrace_here returns a sane structured trace with frames.
[[gnu::noinline]] static void
bt_level_c(int *out_count)
{
    n00b_result_t(n00b_crash_capture_t *) r = n00b_backtrace_here(.resolve = true);
    assert(n00b_result_is_ok(r));
    n00b_crash_capture_t *cap = n00b_result_get(r);
    assert(cap != nullptr);
    assert(cap->regs.valid);
    assert(cap->cause == N00B_CRASH_CAUSE_NONE);
    assert(!cap->reentered);
    assert(cap->frames != nullptr);

    n00b_list_t(n00b_crash_frame_t *) fl = *cap->frames;
    size_t n = n00b_list_len(fl);
    *out_count = (int)n;
    assert(n >= 3); // bt_level_c -> bt_level_b -> bt_level_a -> ...

    // Innermost frame has a pc and (best-effort) a resolved module.
    n00b_crash_frame_t *f0 = n00b_list_get(fl, 0);
    assert(f0->pc != 0);

    // Renderable.
    n00b_string_t *s = n00b_crash_render(cap);
    assert(s != nullptr);
    assert(s->u8_bytes > 0);
}

[[gnu::noinline]] static void
bt_level_b(int *out_count)
{
    bt_level_c(out_count);
}

[[gnu::noinline]] static void
bt_level_a(int *out_count)
{
    bt_level_b(out_count);
}

static void
test_backtrace_here_basic(void)
{
    int count = 0;
    bt_level_a(&count);
    printf("  [PASS] backtrace_here_basic (frames=%d)\n", count);
}

// (c) NEED_NONGC_DEST: with the world stopped and a GC-heap dest, capture must
//     err; with an explicit non-GC dest, it must succeed.
static void
test_need_nongc_dest(void)
{
    n00b_allocator_t *sys = n00b_system_allocator(); // non-moving, safe under STW

    n00b_stop_the_world();
    // GC-heap dest (nullptr resolves to the GC heap for the manual path) while
    // stopped -> NEED_NONGC_DEST.
    n00b_result_t(n00b_crash_capture_t *) bad =
        n00b_crash_capture(.dest = n00b_default_allocator());
    bool got_err = n00b_result_is_err(bad);

    // Explicit non-GC dest while stopped -> succeeds.
    n00b_result_t(n00b_crash_capture_t *) good = n00b_crash_capture(.dest = sys);
    bool got_ok = n00b_result_is_ok(good);
    n00b_restart_the_world();

    assert(got_err);
    assert(n00b_result_get_err(bad) == (n00b_err_t)N00B_CRASH_ERR_NEED_NONGC_DEST);
    assert(got_ok);
    n00b_crash_capture_t *cap = n00b_result_get(good);
    assert(cap != nullptr);
    assert(cap->dest_arena == (uintptr_t)sys);
    assert(cap->regs.valid);

    printf("  [PASS] need_nongc_dest (err+ok both observed)\n");
}

// (b-substrate) Recursion guard: capture from inside a capture yields a
//     degraded result, not a re-crash.  We simulate re-entry via the public
//     surface by capturing within the render of a capture's frame walk is not
//     reachable; instead we drive nested captures on the same thread by reusing
//     the depth contract: a second capture WHILE the first is mid-flight cannot
//     be expressed without a fault, so here we validate the guard's steady-state
//     invariant -- the depth counter returns to 0 after a normal capture (a
//     non-zero residual would mean a future legitimate fault is suppressed).
static void
test_recursion_guard_balanced(void)
{
    // Many sequential captures must each succeed (guard balanced each time).
    for (int i = 0; i < 64; i++) {
        n00b_result_t(n00b_crash_capture_t *) r =
            n00b_crash_capture(.dest = n00b_system_allocator());
        assert(n00b_result_is_ok(r));
        n00b_crash_capture_t *cap = n00b_result_get(r);
        assert(!cap->reentered); // never spuriously flagged
    }
    printf("  [PASS] recursion_guard_balanced (64 captures, none degraded)\n");
}

// (scratch growth) A tiny configured cap still produces a well-formed capture;
//     deep stacks grow scratch via registry-free mmap.
static void
test_scratch_growth(void)
{
    n00b_result_t(n00b_crash_capture_t *) r =
        n00b_crash_capture(.dest = n00b_system_allocator(), .max_frames = 4);
    assert(n00b_result_is_ok(r));
    n00b_crash_capture_t *cap = n00b_result_get(r);
    assert(cap->frames != nullptr);
    n00b_list_t(n00b_crash_frame_t *) fl = *cap->frames;
    assert(n00b_list_len(fl) <= 4);
    printf("  [PASS] scratch_growth (capped frames=%zu)\n", n00b_list_len(fl));
}

// (marshal roundtrip) With the binary's gcmap index populated (via
//     n00b-gcmap-index --exec), the capture's precise per-type layout resolves
//     and a whole capture marshals + unmarshals with its scalar state + frame
//     graph intact and still renders.
[[gnu::noinline]] static void
mr_level_b(void)
{
    n00b_result_t(n00b_crash_capture_t *) r = n00b_backtrace_here(.resolve = true);
    assert(n00b_result_is_ok(r));
    n00b_crash_capture_t *cap = n00b_result_get(r);
    assert(cap->frames != nullptr);

    uint32_t  want_captured = cap->frames_captured;
    uintptr_t want_pc       = cap->regs.pc;
    uint8_t   want_arch     = (uint8_t)cap->regs.arch;

    n00b_buffer_t *buf = n00b_marshal(cap);
    assert(buf != nullptr);

    n00b_list_t(void *) roots = n00b_unmarshal(buf);
    assert(n00b_list_len(roots) >= 1);

    n00b_crash_capture_t *back = n00b_list_get(roots, 0);
    assert(back != nullptr);
    assert(back->frames_captured == want_captured);
    assert(back->regs.pc == want_pc);
    assert((uint8_t)back->regs.arch == want_arch);
    assert(back->frames != nullptr);
    assert(n00b_list_len(*back->frames) == (size_t)want_captured);

    n00b_string_t *s = n00b_crash_render(back);
    assert(s != nullptr && s->u8_bytes > 0);

    printf("  [PASS] marshal_roundtrip (frames=%u, regs+frames+render intact)\n",
           want_captured);
}

static void
test_marshal_roundtrip(void)
{
    mr_level_b();
}

int
main(int argc, char *argv[])
{
#if !defined(_WIN32)
    // Crash-child mode: dispatched by the parent via fork+exec.  Runs one
    // faulting case in this pristine process, then aborts (or _exit(42)s if no
    // fault occurred).
    if (argc >= 2 && strncmp(argv[1], "--crash-child=", 14) == 0) {
        crash_child_run(argv[1] + 14, argc, argv);
        _exit(42); // sentinel: the worker never faulted
    }
#endif

    printf("test_crash:\n");

    // Phases 3+4 first: fork+exec the crash children while the parent is still
    // single-threaded (before it inits n00b).
#if !defined(_WIN32)
    test_crash_overflow_delivers(argv[0]);
    test_crash_segv_delivers(argv[0]);
    test_crash_no_handler_aborts(argv[0]);
    test_crash_log_fd_records(argv[0]);
#else
    printf("  [SKIP] crash delivery (Windows VEH path is written-only)\n");
#endif

    // Phases 1+2 in the main process.
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);
    test_guard_range_cached();
    test_altstack_installed_per_worker();

    // Structured-capture API (new crash_capture surface).
    test_backtrace_here_basic();
    test_recursion_guard_balanced();
    test_scratch_growth();
    test_need_nongc_dest();
    test_marshal_roundtrip();

    printf("All crash tests passed.\n");
    n00b_shutdown();
    return 0;
}
