// The global lock only needs to run at times where it's important
// that all threads are stopped / synchronized.
//
// This is mainly (but not exclusively) when we need to do garbage
// collection; we don't want threads to be mucking w/ memory while we
// are copying data.
//
// We generally would like to avoid contention and cache
// synchronization, so instead of one global lock, the STW works like
// this:
//
// There is one 'stop the world' mutex that must be acquired before
// you can actually begin the process. Then, when you have the mutex,
// you iterate through the global list of threads, and set the STW
// bit in their self-lock futex. Every thread that checks in or.

// 'self-lock' futex to the value 0xffffffff.
//
// Every time a thread is about to call a function that will suspend
// it, any time it uses memory management routines, and every loop
// through the interpreter, the thread will store ~0 into
// thread->wait_futex to indicate it's in the 'self-futex'. If the
// sentinel has been added to the futex by the STW, then that thread
// will block until the STW finishes the stop the world process.
//
// After the STW runs through all threads once, it effectively
// busy-waits.  It keeps iterating through all threads, looking to see
// if they're suspended on their own futex, or otherwise waiting.
//
// For waiting threads, they also ensure wait on their self-lock when
// they resume, so once the STW thread has placed the lock, as long as
// the thread is still in a wait state, all is good.
//
// At that point, the STW thread proceeds, until it is time to restart
// the world.
//
// When it comes time to do that, it goes back through and resets
// the self-lock for each thread to its expected value.
//
// For any thread that was blocked on their self-lock, they then
// ensure that the STW is unlocked before proceeding.
//
// We could use a RW lock for the STW instead; that may end up just as
// good; yes, there'd be a lot more reading of the same memory
// address, but it wouldn't often be modified (on stop-the-world,
// suspend and resume), so probably not much of an issue.
//
// Still, this is simple enough, and doesn't allow nesting of suspends
// / resumes, which I prefer. I might not change it.

#define N00B_USE_INTERNAL_API

#include <time.h>

#include "n00b.h"
#include "core/runtime.h"
#include "core/stw.h"
#include "core/thread.h"
#include "core/futex.h"

#if defined(__APPLE__) && defined(__aarch64__)
// WP-4 (D-040): preemptive suspension of a RUNNING thread on macOS uses the Mach
// thread-control surface (thread_suspend/thread_get_state/thread_resume) on the
// worker's stored thread port — no signal, synchronous.  These are kernel/Mach
// calls, not libpthread (D-002/D-009).
#include <mach/mach.h>
#include <mach/thread_act.h>
#endif

#if defined(__linux__)
// WP-4 (D-040): Linux has no portable suspend-other-thread syscall, so
// preemptive STW uses a dedicated realtime signal delivered via a raw tgkill;
// the TARGET's handler captures its own registers from the ucontext and parks.
// signal.h/ucontext.h/syscall are kernel ABI surfaces (not libpthread).
// [WRITTEN to spec; the Darwin dev box cannot exercise this — host-verified
// later, D-026/D-028.]
#include <signal.h>
#include <ucontext.h>
#include <sys/syscall.h>
#include <unistd.h>

// Raw RT signal number (NOT the SIGRTMIN libc macro — __libc_current_sigrtmin()
// is a glibc call).  40 sits above NPTL's reserved low RT range (32-34) and
// below SIGRTMAX (64), distinct from SIGSEGV/SIGBUS (WP-3b) and the conduit
// fd-multiplex signals.  (D-040, user-chosen.)
#define N00B_STW_SUSPEND_SIG 40
#endif

#if defined(_WIN32)
// WP-4 (D-040): Windows suspends SYNCHRONOUSLY like macOS — SuspendThread +
// GetThreadContext on a handle opened from the worker's thread id; no signal,
// no handler.  [WRITTEN to spec; the Darwin dev box cannot exercise this —
// host-verified later, D-026/D-028.]
#include <windows.h>
#endif

static inline int32_t
get_tid()
{
    // Migrated off the former thread_local __n00b_thread_self to the
    // runtime-owned struct via n00b_thread_self() (WP-001 Phase 2).  This
    // is an access-pattern migration only; the STW algorithm is unchanged
    // (its redesign is WP-004).
    n00b_thread_t *self = n00b_thread_self();
    return self == nullptr ? -1 : self->id_info.parts.id;
}

#if defined(__linux__)
// WP-4 (D-040) Linux suspend-signal handler.  Runs IN SIGNAL CONTEXT on the
// TARGET thread (delivered by the STW initiator via tgkill), on the target's
// NORMAL stack (not an altstack) — so n00b_thread_self(), and thus this
// function's ncc gc_stack_push prologue, resolve correctly.  It captures the
// interrupted register file from the ucontext for the GC's conservative
// top-frame scan (D-007/D-031), publishes "parked", then spins until the world
// restarts.  Async-signal-safe: ucontext reads, atomic stores, and a RAW futex
// wait (NOT n00b_futex_wait — that calls n00b_thread_checkin) — no alloc/lock.
// [Host-verified later — D-026/D-028.]
static void
_n00b_stw_suspend_handler(int sig, siginfo_t *si, void *uctx)
{
    (void)sig;
    (void)si;

    n00b_thread_t *self = n00b_thread_self();
    if (self == nullptr) {
        return; // not a registered n00b thread — nothing to park
    }

    // AS-safe runtime access (n00b_get_runtime() asserts; not signal-safe).
    if (!n00b_option_is_set(n00b_default_runtime)) {
        return;
    }
    n00b_runtime_t *rt = n00b_option_get_or_else(n00b_default_runtime, nullptr);
    if (rt == nullptr) {
        return;
    }

    // Capture the interrupted SP + GP registers.  SP -> stack_top drives the
    // existing conservative C-stack scan; the GP registers are conservatively
    // scanned as part of the whole-thread-struct scan (gc_captured_regs lives in
    // n00b_thread_t — gc.c scan_thread_state covers it).
    ucontext_t *uc = (ucontext_t *)uctx;
#if defined(__aarch64__)
    self->stack_top = (void *)(uintptr_t)uc->uc_mcontext.sp;
    for (int i = 0; i < 31; i++) { // x0-x30
        self->gc_captured_regs[i] = (uint64_t)uc->uc_mcontext.regs[i];
    }
#elif defined(__x86_64__)
    self->stack_top = (void *)(uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
    int n = 0;
    for (int i = 0; i < NGREG && n < 31; i++) {
        self->gc_captured_regs[n++] = (uint64_t)uc->uc_mcontext.gregs[i];
    }
#else
#error "WP-4 Linux suspend handler: add ucontext register capture for this arch"
#endif

    n00b_atomic_store(&self->gc_preempt_suspended, true);

    // Park until _n00b_restart_the_world clears rt->stw (+ futex-wakes
    // stw_generation).  Raw futex wait only — the regs are already captured, and
    // n00b_futex_wait's embedded checkin must NOT run in signal context.
    while (n00b_atomic_load(&rt->stw) != N00B_NO_OWNER) {
        uint32_t        gen  = n00b_atomic_load(&rt->stw_generation);
        struct timespec tout = {.tv_sec = 0, .tv_nsec = 1000 * 1000};
        (void)n00b_futex_wait_timespec(&rt->stw_generation, gen, &tout);
    }

    n00b_atomic_store(&self->gc_preempt_suspended, false);
}
#endif // __linux__

// WP-4 (D-040): install the preemptive-STW suspend-signal handler.  Called once
// from n00b_init.  No-op where suspension needs no signal (macOS Mach / Windows
// SuspendThread).
void
n00b_stw_init(void)
{
#if defined(__linux__)
    struct sigaction sa = {};
    sa.sa_sigaction     = _n00b_stw_suspend_handler;
    sa.sa_flags         = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    (void)sigaction(N00B_STW_SUSPEND_SIG, &sa, nullptr);
#endif
}

// WP-4 (D-040/D-041): preemptively stop a RUNNING thread and capture the
// register state the GC needs.  Returns true if the thread is now suspended with
// its registers captured (`gc_preempt_suspended` set); false if it could not be
// suspended (no port yet / Mach failure), in which case the caller falls back to
// the cooperative wait.  Safe because the collector holds ONLY the STW lock
// (D-041): a thread frozen mid-allocation cannot deadlock the GC.
//
// On non-macOS platforms this is a no-op returning false, so those OSes keep the
// cooperative path until their preemptive backends land (Linux RT-signal /
// Windows SuspendThread — D-040, host-verified later).
static bool
_n00b_preempt_suspend_capture(n00b_thread_t *t)
{
#if defined(__APPLE__) && defined(__aarch64__)
    mach_port_t port = (mach_port_t)t->os_thread_port;
    if (port == 0) {
        return false; // pre-registration window: no control port yet.
    }
    if (thread_suspend(port) != KERN_SUCCESS) {
        return false;
    }

    arm_thread_state64_t   st;
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    if (thread_get_state(port,
                         ARM_THREAD_STATE64,
                         (thread_state_t)&st,
                         &count)
        != KERN_SUCCESS) {
        (void)thread_resume(port);
        return false;
    }

    // SP → stack_top (the interrupted top-frame bound the conservative C-stack
    // scan uses).  __sp is never PAC-signed.  x0-x28/fp/lr → captured GP regs,
    // scanned conservatively (data pointers in x* are not PAC-signed; a PAC'd lr
    // simply fails the alloc-header validation and is harmlessly rejected).
    t->stack_top = (void *)(uintptr_t)st.__sp;
    for (int i = 0; i < 29; i++) {
        t->gc_captured_regs[i] = st.__x[i];
    }
    t->gc_captured_regs[29] = st.__fp;
    t->gc_captured_regs[30] = st.__lr;
    n00b_atomic_store(&t->gc_preempt_suspended, true);
    return true;
#elif defined(__linux__)
    // Async path (D-040): signal the target; its handler captures its own
    // registers + parks (sets gc_preempt_suspended), then we wait for that.
    if (t->os_tid == 0) {
        return false; // pre-launch window: tid not captured yet.
    }
    long tgid = syscall(SYS_getpid); // thread-group id == process id
    if (syscall(SYS_tgkill, tgid, (long)(int32_t)t->os_tid, N00B_STW_SUSPEND_SIG)
        != 0) {
        return false; // delivery failed (e.g. the thread just exited)
    }
    // Wait for the handler to acknowledge it has parked + captured.  DF-4 means
    // we only signal RUNNING threads, which take the signal promptly; a short
    // spin is the handshake (the handler does not wake a futex on this flag).
    while (!n00b_atomic_load(&t->gc_preempt_suspended)) {
    }
    return true;
#elif defined(_WIN32)
    // Synchronous (like macOS): open a handle from the stored tid, suspend, and
    // read the register file.  Suspend count lives on the thread (not the
    // handle), so we can close the handle and re-open to resume.
    if (t->os_tid == 0) {
        return false;
    }
    HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
                          FALSE,
                          (DWORD)t->os_tid);
    if (h == nullptr) {
        return false;
    }
    if (SuspendThread(h) == (DWORD)-1) {
        CloseHandle(h);
        return false;
    }
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(h, &ctx)) {
        ResumeThread(h);
        CloseHandle(h);
        return false;
    }
#if defined(_M_X64) || defined(__x86_64__)
    t->stack_top          = (void *)(uintptr_t)ctx.Rsp;
    const uint64_t gp[] = {ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi,
                           ctx.Rbp, ctx.R8,  ctx.R9,  ctx.R10, ctx.R11, ctx.R12,
                           ctx.R13, ctx.R14, ctx.R15};
    for (int i = 0; i < 15; i++) {
        t->gc_captured_regs[i] = gp[i];
    }
#elif defined(_M_ARM64) || defined(__aarch64__)
    t->stack_top = (void *)(uintptr_t)ctx.Sp;
    for (int i = 0; i < 29; i++) { // X0-X28
        t->gc_captured_regs[i] = ctx.X[i];
    }
    t->gc_captured_regs[29] = ctx.Fp;
    t->gc_captured_regs[30] = ctx.Lr;
#else
#error "WP-4 Windows suspend: add CONTEXT register capture for this arch"
#endif
    n00b_atomic_store(&t->gc_preempt_suspended, true);
    CloseHandle(h);
    return true;
#else
    (void)t;
    return false;
#endif
}

// WP-4: release a thread the STW initiator preemptively suspended.  Clears the
// flag BEFORE resuming so a later scan never trusts stale captured registers.
static void
_n00b_preempt_resume(n00b_thread_t *t)
{
#if defined(__APPLE__) && defined(__aarch64__)
    if (n00b_atomic_load(&t->gc_preempt_suspended)) {
        n00b_atomic_store(&t->gc_preempt_suspended, false);
        // Zero the captured register file so a later collection's whole-struct
        // conservative scan (gc.c scan_thread_state scans all of n00b_thread_t,
        // which includes gc_captured_regs) does not keep re-rooting stale
        // register values and retaining their targets as floating garbage.
        for (int i = 0; i < 31; i++) {
            t->gc_captured_regs[i] = 0;
        }
        (void)thread_resume((mach_port_t)t->os_thread_port);
    }
#elif defined(__linux__)
    // The target's signal handler self-resumes: it spins until rt->stw ==
    // N00B_NO_OWNER, which _n00b_restart_the_world set + futex-woke
    // (stw_generation) BEFORE this resume loop runs.  The handler then clears its
    // own gc_preempt_suspended (and the captured regs go stale but are re-stamped
    // on the next suspend) and returns to the interrupted PC.  Nothing to do here.
    (void)t;
#elif defined(_WIN32)
    // Synchronous resume (like macOS): clear the flag + captured regs, then
    // ResumeThread via a freshly opened handle (suspend count is on the thread).
    if (n00b_atomic_load(&t->gc_preempt_suspended)) {
        n00b_atomic_store(&t->gc_preempt_suspended, false);
        for (int i = 0; i < 31; i++) {
            t->gc_captured_regs[i] = 0;
        }
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, (DWORD)t->os_tid);
        if (h != nullptr) {
            ResumeThread(h);
            CloseHandle(h);
        }
    }
#else
    (void)t;
#endif
}

void
_n00b_stop_the_world(char *loc)
{
    n00b_runtime_t *rt = n00b_get_runtime();

    _n00b_thread_suspend(loc);

    int32_t tid   = get_tid();
    int32_t owner = n00b_atomic_load(&rt->stw);

    if (owner == tid) {
        rt->stw_nesting++;
        return;
    }

    int32_t expected;

    do {
        int32_t cur;

        while ((cur = (int32_t)n00b_atomic_load(&rt->stw)) != N00B_NO_OWNER) {
            uint32_t generation = n00b_atomic_load(&rt->stw_generation);
            n00b_futex_wait(&rt->stw_generation, generation, 1000 * 1000);
        }

        expected = N00B_NO_OWNER;
    } while (!n00b_cas(&rt->stw, (uint32_t *)&expected, tid));

    assert(n00b_atomic_load(&rt->stw) == (uint32_t)tid);

    int n = (int)rt->max_threads;

    // Loop through every single thread and add the STW bit to their
    // state, which will alert them to go wait on the STW.

    n00b_thread_t *t;

    while (n--) {
        t = n00b_atomic_load(&rt->threads[n].thread);
        if (!t || t == n00b_thread_self()) {
            continue;
        }

        n00b_atomic_or(&t->self_lock, N00B_STW);
    }

    // Bring every other live thread to a GC-safe stop.  A thread is safe once
    // its live heap pointers are visible to the GC: either it self-parked with
    // registers spilled (BLOCKING = checkpointed in wait_for_stw_release; or
    // SUSPEND = parked in a blocking syscall via n00b_run_blocking), OR — WP-4 —
    // the initiator PREEMPTIVELY suspends it and captures its register file.
    // Preemption is what lets STW reclaim a pure-compute thread that never
    // reaches a cooperative checkin (the case the old cooperative-only barrier
    // could hang on forever).
    n = (int)rt->max_threads;

    while (n--) {
        while (true) {
            t = n00b_atomic_load(&rt->threads[n].thread);
            if (!t || t == n00b_thread_self()) {
                break;
            }

            uint32_t state = n00b_atomic_load(&t->self_lock);
            // DF-4: a thread already parked in a blocking syscall (SUSPEND) or at
            // a checkin (BLOCKING) is GC-safe with registers spilled — leave it;
            // do not preemptively suspend it (sidesteps EINTR for the I/O drivers).
            if (state & (N00B_SUSPEND | N00B_BLOCKING)) {
                break;
            }

            // RUNNING thread: preemptively suspend + capture its registers
            // (WP-4 / D-040; safe because the GC holds only the STW lock — D-041).
            // On success the world is genuinely stopped for it without waiting on
            // a cooperative checkin.
            if (_n00b_preempt_suspend_capture(t)) {
                break;
            }

            // Preemption unavailable (no control port yet, or a platform whose
            // preemptive backend has not landed — Linux/Windows): fall back to the
            // cooperative path — mark STW and re-loop until it self-parks.  A
            // thread can also exit between the marking pass and here, so reload
            // the slot each turn (the `!t` check above breaks once it clears its
            // registration) to avoid spinning on a stale pointer.
            n00b_atomic_or(&t->self_lock, N00B_STW);
        }
    }

    rt->stw_nesting = 1;

    _n00b_thread_resume(loc);
}

void
_n00b_restart_the_world(char *loc)
{
    int32_t         tid   = get_tid();
    n00b_runtime_t *rt    = n00b_get_runtime();
    int32_t         owner = n00b_atomic_load(&rt->stw);

    if (owner != tid) {
        abort();
    }

    assert(rt->stw_nesting > 0);

    if (--rt->stw_nesting) {
        return;
    }

    n00b_barrier();
    int n = (int)rt->max_threads;

    n00b_thread_t *t;

    while (n--) {
        t = n00b_atomic_load(&rt->threads[n].thread);
        if (!t || t == n00b_thread_self()) {
            continue;
        }

        n00b_atomic_and(&t->self_lock, ~N00B_STW);
    }

    atomic_store(&rt->stw, N00B_NO_OWNER);

    n00b_atomic_add(&rt->stw_generation, 1);
    n00b_futex_wake(&rt->stw_generation, true);
    n00b_futex_wake(&rt->stw, true);

    // WP-4: resume threads we PREEMPTIVELY suspended (vs. those that self-parked
    // on the futex, woken above).  Done AFTER rt->stw is released + bits cleared
    // so a resumed thread that immediately hits a checkin sees a clean state.  A
    // preempted thread resumes at its interrupted PC (not a checkin), so this is
    // the only thing that unblocks it.
    n = (int)rt->max_threads;
    while (n--) {
        t = n00b_atomic_load(&rt->threads[n].thread);
        if (!t || t == n00b_thread_self()) {
            continue;
        }
        _n00b_preempt_resume(t);
    }
}

const struct timespec stw_check_timeout = {
    .tv_sec  = 0,
    .tv_nsec = 10000,
};

void
n00b_wait_for_stw_release(void)
{
    n00b_runtime_t *rt         = n00b_get_runtime();
    n00b_jmp_buf_t  save_state = {};
    n00b_thread_t  *self       = n00b_thread_self();

    // self() is nullable now (the pre-registration window, D-004/D-014): a
    // thread that has not yet published its stack bounds is not a STW
    // participant, so there is nothing to wait on.  Guard only — the STW
    // algorithm is unchanged (its redesign is WP-004).
    if (self == nullptr) {
        return;
    }

    n00b_capture_stack_top(self);
    int32_t  cur        = n00b_atomic_load(&rt->stw);
    uint32_t generation = n00b_atomic_load(&rt->stw_generation);

    if (cur == get_tid()) {
        return;
    }

    if (!n00b_setjmp(&save_state)) {
        // n00b_setjmp() must capture callee-saved registers BEFORE we
        // announce N00B_BLOCKING — the STW initiator uses that bit
        // to decide save_state is ready to scan.  Swapping the order
        // races: initiator sees the bit, scans an uninitialised
        // save_state.
        n00b_atomic_or(&self->self_lock, N00B_BLOCKING);

        while (cur != N00B_NO_OWNER) {
            // Use the version that doesn't check the STW when it's
            // signaled.  Wait on a generation futex instead of the owner
            // word: the same owner can run consecutive STW cycles, so the
            // owner value has an ABA shape (tid -> no-owner -> same tid).
            n00b_futex_wait_timespec(&rt->stw_generation,
                                     generation,
                                     (void *)&stw_check_timeout);
            generation = n00b_atomic_load(&rt->stw_generation);
            cur        = n00b_atomic_load(&rt->stw);
        }

        n00b_longjmp(&save_state, 1);
    }
    uint32_t old_state = n00b_atomic_and(&self->self_lock,
                                         ~N00B_BLOCKING);
    uint32_t       new_state = n00b_atomic_load(&self->self_lock);
    int32_t  owner     = n00b_atomic_load(&rt->stw);

    if (((old_state | new_state) & N00B_STW)
        && owner != N00B_NO_OWNER
        && owner != get_tid()) {
        n00b_thread_checkin();
    }
}

void
n00b_thread_checkin(void)
{
    n00b_thread_t *self = n00b_thread_self();

    // self() is nullable in the pre-registration window (D-004/D-014); an
    // unregistered thread is not a STW participant and has no self_lock to
    // check.  Guard only — STW semantics unchanged (WP-004).
    if (self == nullptr) {
        return;
    }

    int val = n00b_atomic_load(&self->self_lock);

    if (!val) {
        return;
    }

    if (n00b_atomic_load(&self->self_lock) & N00B_STW) {
        // n00b_wait_for_stw_release sets N00B_BLOCKING itself, after
        // n00b_setjmp() has captured callee-saved registers.  Setting it here
        // first races: the STW initiator may see the bit and start
        // scanning before save_state is initialised.
        n00b_wait_for_stw_release();
    }
}

// 'suspend' means we are about to go into some kind of state where we
// might not check in (at least not soon). We actually can still keep
// running, but we promise that we are not doing ANYTHING in scope for
// a STW. So we cannot be using heap memory or locks, etc.
//
// The intent here is we call this, then call sleep(), poll() or
// any other potentially blocking call we need to make, then call
// n00b_thread_resume() immediately on getting woken.
void
_n00b_thread_suspend(char *loc)
{
    n00b_thread_t *self = n00b_thread_self();

    // self() is nullable in the pre-registration window (D-004/D-014); an
    // unregistered thread has no self_lock to set.  Guard only.
    if (self == nullptr) {
        return;
    }

    n00b_atomic_or(&self->self_lock, N00B_SUSPEND);
}

void
_n00b_thread_resume(char *loc)
{
    (void)loc;

    // Threads can try to resume during a STW. We should go ahead and
    // turn off 'SUSPEND', but then we will hit the STW when we do the
    // check-in at the end.
    //
    // However, the STW thread should quick-return; it shouldn't have
    // any contention, unless it is trying to access a resource that's
    // already locked at the time of the STW, which should be a no-no.
    //
    // If that happens, the system will deadlock.
    n00b_runtime_t *rt   = n00b_get_runtime();
    n00b_thread_t  *self = n00b_thread_self();

    // self() is nullable in the pre-registration window (D-004/D-014); an
    // unregistered thread has no self_lock to clear and is not a STW
    // participant, so there is nothing to resume.  Guard only.
    if (self == nullptr) {
        return;
    }

    n00b_atomic_and(&self->self_lock, ~N00B_SUSPEND);

    int val = n00b_atomic_load(&rt->stw);
    if (val == get_tid()) {
        return;
    }

    n00b_thread_checkin();
}
