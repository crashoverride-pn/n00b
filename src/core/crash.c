// WP-3b crash detection/delivery + guard-page stack-overflow handler.
//
// The fault handler runs on a per-thread alternate signal stack (SA_ONSTACK)
// so it survives a stack overflow.  CRITICAL: ncc GC-instruments every function
// it compiles — _n00b_crash_handler's own prologue emits an n00b_gc_stack_push
// that calls n00b_thread_self(), which masks the SP to a callstack region and
// reads the slot ID word at region_start + S - 8.  So the altstack cannot be a
// plain mmap (self() would mask to a wrong/garbage base and fault BEFORE the
// handler body).  Instead the altstack IS a full n00b callstack region (S-
// aligned, with the SP-mask geometry), and we stamp the owning thread's slot id
// into its ID word — so self() (and thus the prologue) resolves correctly when
// the handler runs on it.
//
// LIFETIME (D-039, superseding D-038's per-slot-forever model): the altstack is
// drawn from the shared callstack pool by the SPAWNER (a worker cannot allocate
// its own at launch — its launch-time default allocator returns guard-band
// memory) and returned to that pool by the REAPER at OS-confirmed death, exactly
// like the worker's primary callstack.  This bounds the live set to (live
// workers + pool keep-N) rather than N00B_THREADS_MAX * S.  It lives on the
// per-WORKER struct (n00b_thread_t::altstack), NOT the shared slot record, so a
// slot reused before its prior worker is reaped can never cause the reaper to
// return a live worker's region.  (Cost: a second S-sized pool region per live
// worker — an optimization opportunity, tracked.)

#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/crash.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "core/callstack.h" // n00b_callstack_pool_get + region geometry
#include "core/mmaps.h"

// Output + process-exit here go through core/syscall.h's RAW (libc-free)
// syscalls, NOT libc write()/_exit().  Two reasons: (1) no-libc — write()/_exit()
// are libc symbols this project removes (NCC.md "NO LIBC ALLOWED"); (2) a fault
// handler runs in async-signal context on a thread whose TSD may be wrecked, so
// the conduit/print stack is unusable (locks + allocation) and even libc's
// write() (errno-TLS) is unsafe — a bare syscall instruction takes no lock and
// touches no TLS.  sigaltstack/sigaction are the kernel signal surface (no n00b
// wrapper; permitted raw in a .c file per NCC.md, as callstack.c uses mprotect).
#if !defined(_WIN32)
#include <signal.h> // sigaltstack/sigaction/stack_t (kernel signal surface, not libpthread)
#include "core/syscall.h" // n00b_raw_write / n00b_raw_exit — libc-free, AS-safe
#endif

void
n00b_crash_install_altstack(n00b_callstack_t *as_cs)
{
#if !defined(_WIN32)
    n00b_thread_t *self = n00b_thread_self();
    if (self == nullptr || as_cs == nullptr) {
        return; // best-effort: run without an altstack
    }

    // The region is supplied by the caller (drawn from the shared callstack pool
    // by the spawner via the bundle, or by n00b_crash_init for the main thread)
    // and returned to that pool at OS-confirmed death by the reaper — the SAME
    // bounded lifetime as the worker's primary callstack (D-039).  We do NOT
    // allocate here: a worker's launch-time default allocator returns guard-band
    // memory, and a never-freed per-slot region explodes to N00B_THREADS_MAX * S
    // (D-038's discarded model).

    // Stamp THIS thread's slot id into the region's ID word (region_start + S - 8
    // — the geometry n00b_thread_self() reads), so self() resolves back to this
    // thread when the handler (and its ncc gc_stack_push prologue) runs here.
    // Re-stamped on every install because a pooled region carries the prior
    // owner's id.
    uint64_t *id_word = (uint64_t *)((char *)as_cs->region_start
                                     + as_cs->region_size
                                     - N00B_CALLSTACK_ID_WORD_SIZE);
    *id_word          = (uint64_t)(uint32_t)self->id_info.parts.id;

    // Publish on the PER-WORKER struct (reached by the handler's range-scan via
    // rt->threads[i].thread->altstack) so a fault on this region maps back to
    // this thread.  On the struct, NOT the shared slot record: a slot reused
    // before this worker is reaped must not let the reaper return a live
    // worker's altstack (D-039).  The reaper clears it and returns the region at
    // death, so a stale slot never misleads the scan.
    n00b_atomic_store(&self->altstack, as_cs);

    // Hand the usable region to sigaltstack, reserving the top page so the
    // signal frame (placed at the high end, growing down) cannot clobber the ID
    // word at region_start + S - 8.
    char  *lo   = (char *)as_cs->stack_low;
    char  *hi   = (char *)as_cs->stack_high;
    size_t resv = (size_t)n00b_page_size;
    if ((size_t)(hi - lo) <= resv) {
        return;
    }

    stack_t ss = {
        .ss_sp    = lo,
        .ss_size  = (size_t)(hi - lo) - resv,
        .ss_flags = 0,
    };
    (void)sigaltstack(&ss, nullptr);
#else
    // Windows: VEH runs on the faulting stack (with the OS stack-guard
    // reserve); no alternate-stack install. Written-only (host-verified later).
    (void)0;
#endif
}

#if !defined(_WIN32)

// Async-signal-safe one-line write to stderr via a raw, libc-free syscall
// (no stdio/locks/alloc/errno-TLS).
static void
_n00b_crash_write(const char *s)
{
    size_t n = 0;
    while (s[n] != '\0') {
        n++;
    }
    n00b_raw_write(2, s, n);
}

// SIGSEGV/SIGBUS fault handler.  Runs in signal context on the faulting
// thread's alternate stack (SA_ONSTACK), which is an n00b callstack stamped
// with this thread's slot id — so n00b_thread_self() (and the ncc-emitted
// gc_stack_push in this function's own prologue) resolve correctly here.
// Async-signal-safe: stable reads, raw write/exit syscalls.  Never returns into
// the faulting context (abort-after-handler, D-032 Q3).
static void
_n00b_crash_handler(int sig, siginfo_t *si, void *uctx)
{
    (void)sig;
    (void)uctx;

    // Resolve the FAULTING thread by the altstack region we are running on (a
    // local's address lies in that slot's altstack-callstack region).  We do
    // NOT trust n00b_thread_self() for this: self() resolves via the altstack's
    // stamped ID word, which is enough to keep this function's gc_stack_push
    // PROLOGUE from faulting, but the range scan is what reliably identifies
    // which thread overflowed.  Async-signal-safe: stable per-slot reads.
    volatile int marker = 0;
    uintptr_t    hsp    = (uintptr_t)(void *)&marker;

    // AS-safe runtime access: n00b_get_runtime() goes through n00b_option_get,
    // whose assert() is NOT async-signal-safe.  Read the option directly; if the
    // runtime is not yet set (a fault before init completes), abort cleanly.
    if (!n00b_option_is_set(n00b_default_runtime)) {
        _n00b_crash_write("n00b: fatal: fault before runtime init\n");
        n00b_raw_exit(139);
    }
    n00b_runtime_t *rt       = n00b_option_get_or_else(n00b_default_runtime, nullptr);
    n00b_thread_t  *faulting = nullptr;

    if (rt != nullptr && rt->threads != nullptr) {
        for (uint32_t i = 0; i < rt->max_threads; i++) {
            // The altstack lives on the per-worker thread struct (D-039), so
            // reach it via the slot's published thread pointer.  Both reads are
            // stable (user_pool, non-moving) and async-signal-safe.
            n00b_thread_t *t = n00b_atomic_load(&rt->threads[i].thread);
            if (t == nullptr || (uintptr_t)t <= 1) {
                continue; // empty slot or placeholder
            }
            n00b_callstack_t *as = (n00b_callstack_t *)n00b_atomic_load(
                &t->altstack);
            if (as != nullptr) {
                uintptr_t lo = (uintptr_t)as->region_start;
                uintptr_t hi = lo + as->region_size;
                if (hsp >= lo && hsp < hi) {
                    faulting = t;
                    break;
                }
            }
        }
    }

    // Classify: a fault address inside the faulting thread's PROT_NONE guard
    // band is a stack overflow (lock-free range compare on the cached bounds).
    // guard_lo/hi are _Atomic — load with acquire to pair with the owning
    // thread's release store (it stores hi then lo before its altstack install).
    bool overflow = false;
    if (faulting != nullptr && si != nullptr) {
        void *glo = n00b_atomic_load(&faulting->guard_lo);
        void *ghi = n00b_atomic_load(&faulting->guard_hi);
        if (glo != nullptr) {
            uintptr_t fa = (uintptr_t)si->si_addr;
            if (fa >= (uintptr_t)glo && fa < (uintptr_t)ghi) {
                overflow = true;
            }
        }
    }

    _n00b_crash_write(overflow ? "n00b: fatal: stack overflow\n"
                               : "n00b: fatal: invalid memory access\n");

    // Deliver to the faulting thread's registered crash handler (WP-2 surface),
    // if any; then abort regardless (D-032 Q3) — it cannot resume the fault.
    if (faulting != nullptr && faulting->crash_handler != nullptr) {
        faulting->crash_handler(faulting, faulting->crash_handler_data);
    }

    // Abort-after-handler via a RAW exit syscall (n00b_raw_exit) — NOT
    // n00b_abort(): n00b_abort()→libc abort() is not raw-worker-safe (on a
    // pthread-less n00b worker it produced SIGTRAP, observed, not a clean
    // SIGABRT), and is libc besides.  n00b_raw_exit is a bare, async-signal-safe,
    // libc-free exit syscall; 139 (= 128 + SIGSEGV) is n00b's crash code.
    // [TRACKED: making n00b_abort itself raw-worker-safe is a separate no-libc
    // cleanup — it should route through core/syscall.h too.]
    n00b_raw_exit(139);
}

#endif // !_WIN32

void
n00b_crash_init(void)
{
#if !defined(_WIN32)
    // Main-thread altstack (deferred from P2 to here, where the mmap machinery
    // and the default allocator are fully up).  Workers install theirs in the
    // launcher from a bundle-carried pool region; the main thread draws its own
    // here.  Unlike a launching worker, the main thread's default allocator is
    // live, so a callstack-pool MISS (the pool is empty at init) falls back to a
    // clean n00b_callstack_alloc.  The main thread is never reaped, so this one
    // region is held for the runtime's lifetime (exactly one, not per-slot).
    n00b_result_t(n00b_callstack_t *) main_as = n00b_callstack_pool_get();
    n00b_crash_install_altstack(n00b_result_is_ok(main_as)
                                    ? n00b_result_get(main_as)
                                    : nullptr);

    struct sigaction sa = {};
    sa.sa_sigaction     = _n00b_crash_handler;
    sa.sa_flags         = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);

    // NOTE (WP-3b audit): we do not yet CHAIN a pre-existing SIGSEGV handler.
    // No fault handler is installed before n00b_crash_init (conduit/display
    // sigaction sites cover other signals / are armed on demand later); if a
    // SIGSEGV watch is ever armed before init, chaining via the saved oldact is
    // the follow-up.  GC memory-permission checks use poll/read, not faults, so
    // this handler does not intercept GC traffic.
    (void)sigaction(SIGSEGV, &sa, nullptr);
    (void)sigaction(SIGBUS, &sa, nullptr);
#else
    // Windows: AddVectoredExceptionHandler equivalent — written-only,
    // host-verified later (D-026/D-028).
    (void)0;
#endif
}
