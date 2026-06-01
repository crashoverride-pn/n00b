#include <stdio.h>
#include <assert.h>
#include <signal.h>   // sigaltstack / stack_t (Phase 2 probe)
#if !defined(_WIN32)
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
#include "core/mmaps.h"
#include "core/align.h"

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
//   139 = the global handler ran with NO user handler (crash.c's _exit(139))
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
// invoked.  The runtime's global handler would otherwise _exit(139); either way
// the process aborts and never resumes the faulting context (D-032 Q3).
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
run_crash_case(const char *self, const char *flag)
{
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        execl(self, self, flag, (char *)nullptr);
        _exit(43); // exec failed
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return WIFSIGNALED(status) ? (128 + WTERMSIG(status)) : -1;
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
    assert(rc == 139); // fault, no user handler -> global handler -> direct abort
    printf("  [PASS] crash_no_handler_aborts (rc=%d)\n", rc);
}

#endif // !_WIN32

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
#else
    printf("  [SKIP] crash delivery (Windows VEH path is written-only)\n");
#endif

    // Phases 1+2 in the main process.
    n00b_runtime_t rt;
    n00b_init(&rt, argc, argv);
    test_guard_range_cached();
    test_altstack_installed_per_worker();

    printf("All crash tests passed.\n");
    n00b_shutdown();
    return 0;
}
