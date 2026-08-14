#ifndef _WIN32
#include <sys/mman.h>
#include <sys/resource.h>
#include <string.h>
#include <unistd.h>
#else
#include "core/platform.h"
#include <io.h>
#endif

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_time.h>
#include <mach/thread_act.h>
#include <mach/thread_policy.h>
#include <sys/syscall.h>
#endif

#if defined(__linux__)
#include <fcntl.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#if defined(__GLIBC__)
// __libc_single_threaded (glibc >= 2.32): glibc keeps this true until
// pthread_create marks the process multithreaded, and while true it ELIDES
// internal locks (stdio FILE locks, malloc arena locks, ...) as a
// single-threaded fast path.  n00b spawns workers via raw clone(2), NOT
// pthread_create (see _n00b_os_raw_clone below), so glibc never learns the
// process went multithreaded and keeps eliding those locks — two threads then
// race inside libc (e.g. concurrent fprintf(stderr) corrupting the stderr FILE
// buffer -> SIGSEGV; wax#493).  We clear it ourselves at the raw-clone site.
#include <sys/single_threaded.h>
#endif
#endif

#define __N00B_THREAD_INTERNAL

#include "n00b.h"
#include "core/runtime.h"
#include "core/thread.h"
#include "adt/option.h"
#include "core/atomic.h"
#include "core/futex.h"
#include "core/mmaps.h"
#include "core/callstack.h"
#include "core/crash.h"
#include "core/memory_info.h"
#include "core/lock_common.h"
#include "core/mutex.h"
#include "core/rwlock.h"
#include "core/condition.h"
#include "core/alloc.h"
#include "core/epoch.h"
#include "core/stw.h"
#include "core/syscall.h"

#if defined(__linux__)
static bool
n00b_linux_parse_maps_hex(char **cursor, char *end, uintptr_t *out)
{
    uintptr_t value = 0;
    bool      saw   = false;

    while (*cursor < end) {
        unsigned digit;
        char     c = **cursor;

        if (c >= '0' && c <= '9') {
            digit = (unsigned)(c - '0');
        }
        else if (c >= 'a' && c <= 'f') {
            digit = (unsigned)(c - 'a' + 10);
        }
        else if (c >= 'A' && c <= 'F') {
            digit = (unsigned)(c - 'A' + 10);
        }
        else {
            break;
        }

        value = (value << 4) | digit;
        saw   = true;
        (*cursor)++;
    }

    if (!saw) {
        return false;
    }

    *out = value;
    return true;
}

static bool
n00b_linux_maps_line_contains(char     *line,
                              char     *end,
                              uintptr_t target,
                              char    **lowest,
                              char    **highest)
{
    char     *cursor = line;
    uintptr_t start;
    uintptr_t stop;

    if (!n00b_linux_parse_maps_hex(&cursor, end, &start)) {
        return false;
    }

    if (cursor >= end || *cursor != '-') {
        return false;
    }

    cursor++;

    if (!n00b_linux_parse_maps_hex(&cursor, end, &stop)) {
        return false;
    }

    if (target < start || target >= stop) {
        return false;
    }

    *lowest  = (char *)start;
    *highest = (char *)stop;
    return true;
}

static bool
n00b_linux_mapping_bounds_for(void *addr, char **lowest, char **highest)
{
    static const char maps_path[] = "/proc/self/maps";
    long fd = _n00b_raw_linux_syscall4(SYS_openat,
                                       (long)AT_FDCWD,
                                       (long)(uintptr_t)maps_path,
                                       (long)(O_RDONLY | O_CLOEXEC),
                                       0);
    if (fd < 0) {
        return false;
    }

    uintptr_t target = (uintptr_t)addr;
    char      buf[32768];
    size_t    used  = 0;
    bool      found = false;

    for (;;) {
        if (used == sizeof(buf)) {
            used = 0;
        }

        long n = _n00b_raw_linux_syscall3(SYS_read,
                                          fd,
                                          (long)(uintptr_t)(buf + used),
                                          (long)(sizeof(buf) - used));

        if (n < 0) {
            break;
        }

        if (n == 0) {
            if (used != 0
                && n00b_linux_maps_line_contains(buf,
                                                 buf + used,
                                                 target,
                                                 lowest,
                                                 highest)) {
                found = true;
            }
            break;
        }

        used += (size_t)n;

        char *line  = buf;
        char *limit = buf + used;

        while (line < limit) {
            char *nl = line;
            while (nl < limit && *nl != '\n') {
                nl++;
            }

            if (nl == limit) {
                break;
            }

            if (n00b_linux_maps_line_contains(line, nl, target, lowest, highest)) {
                found = true;
                break;
            }

            line = nl + 1;
        }

        if (found) {
            break;
        }

        if (line > buf) {
            used = (size_t)(limit - line);
            memmove(buf, line, used);
        }
    }

    (void)_n00b_raw_linux_syscall1(SYS_close, fd);
    return found;
}
#endif

// Worker-safe sleep (declared in core/platform.h).  n00b workers are raw OS
// threads with no libpthread TSD, so libc nanosleep — a cancellation point that
// derefs that TSD via pthread_testcancel — faults on them (same rationale as the
// raw-syscall poll in stw.c).  We instead wait on a private futex that nobody
// will ever wake, which simply times out after the requested interval;
// __ulock_wait2 / futex(2) / WaitOnAddress touch no TSD.  The loop keeps each
// wait's timeout normalized (< 1s) so it is valid on every backend, and covers
// both multi-second sleeps and any early (spurious) wake.
void
base_nanosleep_ns(uint64_t ns)
{
    n00b_futex_t f;
    n00b_futex_init(&f);

    // Clamp to INT64_MAX ns (~292 yr) so the signed deadline math cannot
    // overflow on an implausibly large request.
    if (ns > (uint64_t)INT64_MAX) {
        ns = (uint64_t)INT64_MAX;
    }
    int64_t deadline = n00b_ns_timestamp() + (int64_t)ns;
    for (;;) {
        int64_t remaining = deadline - n00b_ns_timestamp();
        if (remaining <= 0) {
            return;
        }
        uint64_t chunk = (remaining > 999999999LL) ? 999999999ULL
                                                   : (uint64_t)remaining;
        (void)n00b_futex_wait(&f, 0, chunk);
    }
}

// ============================================================================
// TLS-free identity (D-004 / D-014)
//
// The calling thread's n00b_thread_t no longer lives in thread_local
// storage.  Its canonical home is the permanent n00b_thread_t allocated
// from the GC-visible, non-moving user_pool (WP-3a / D-034), pointed at
// by rt->threads[slot].thread; being a pool it is non-moving, so the GC
// never relocates it (it is GC-OWNED — reachable -> kept, unreferenced ->
// reclaimed — but never moved, unlike a default-arena object).
// n00b_thread_self() recovers the owning slot from the current stack
// pointer with no TLS, no lock, and no interval-tree lookup:
//
//   - Main thread: an O(1) range check against the kernel-stack bounds
//     stored in N00B_MAIN_THREAD_SLOT's record at init.
//   - Worker threads: the Phase-1 masking helper n00b_callstack_id_word
//     reads the id from the fixed offset in the S-aligned callstack
//     region (workers are wired in Phase 3; the branch is dormant here).
// ============================================================================

// Bootstrap thread struct used only during the startup window — after
// the runtime exists but before the main thread's slot is registered.
// Init is single-threaded (only the main thread runs before
// n00b_thread_init returns), so a single struct is safe and non-moving.
// The GC-stack frames the codegen publishes into gc_stack_top during
// early init land here; n00b_thread_init copies them into the registered
// main struct so the frame chain stays continuous across the handoff.
// After registration, n00b_thread_self() never returns this again (the range check
// resolves to the registered struct instead).
//
// Not static: the n00b_thread_self() macro (D-019) references it from
// every translation unit, so it is an extern global declared in thread.h.
n00b_thread_t _n00b_bootstrap_thread = {};

// n00b_thread_self() is a function-like macro (D-019), defined in
// thread.h: ncc emits a GC stack-map push in every framed function's
// prologue, and that push calls n00b_thread_self() — so a framed n00b_thread_self()
// would recurse through its own prologue.  As a macro it has no prologue
// to instrument, and its body is pure atomic loads + masking arithmetic
// (no framed callee, reaching the runtime via the n00b_default_runtime
// global rather than an accessor), keeping the whole identity path below
// the GC instrumentation layer.  The recovery logic that lived here is
// now inlined in that macro.

// Thread-identity accessors.  Out-of-line (not inline in thread.h)
// because each expands the n00b_thread_self() macro, which dereferences
// the full n00b_runtime_t; compiling them here keeps that complete-type
// requirement out of the many headers that include thread.h (e.g.
// lock_common.h).  These are NOT on the GC stack-map push path, so being
// framed functions is safe — only n00b_thread_self() itself must stay
// instrumentation-free (D-019).
int64_t
n00b_thread_unique_id(void)
{
    n00b_thread_t *self = n00b_thread_self();
    return self == nullptr ? 0 : self->id_info.unique_id;
}

int32_t
n00b_thread_id(void)
{
    n00b_thread_t *self = n00b_thread_self();
    return self == nullptr ? 0 : self->id_info.parts.id;
}

int32_t
n00b_thread_generation(void)
{
    n00b_thread_t *self = n00b_thread_self();
    return self == nullptr ? 0 : self->id_info.parts.generation;
}

// OS-level thread id, resolved WITHOUT n00b_thread_self() / the TCB.  The
// critical_execution lock owner is keyed on this (a thread holds the lock
// during its whole init/destroy, when self() is not resolvable), so it must
// not depend on runtime state.  Framed is fine: not on the n00b_thread_self()
// instrumentation path (D-019).
int64_t
n00b_os_thread_id(void)
{
#if defined(__linux__)
    return (int64_t)_n00b_raw_linux_syscall1(SYS_gettid, 0);
#elif defined(__APPLE__) && defined(__aarch64__)
    // n00b workers are RAW Mach threads (thread_create), NOT pthreads, so
    // pthread_threadid_np(NULL, ...) reads a null pthread_t (TSD slot 0 is our
    // minimal block, not a real pthread) and yields 0 — collapsing every raw
    // worker's lock-owner id to 0 and destroying mutual exclusion.  Instead read
    // the Mach thread port from TSD slot 3 (__TSD_MACH_THREAD_SELF) directly off
    // the hardware thread pointer (TPIDRRO_EL0), exactly as os_unfair_lock does.
    // The spawner seeds slot 3 with the thread's thread_create port (raw worker)
    // and the kernel seeds it for the main pthread — a stable, per-thread,
    // process-unique scalar, resolvable with NO TCB / n00b_thread_self() and no
    // send-right minting.  Mask the low 3 reserved bits of the thread pointer.
    uint64_t tpidrro;
    __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(tpidrro));
    uint64_t *tsd = (uint64_t *)(uintptr_t)(tpidrro & ~(uint64_t)0x7);
    if (tsd == nullptr) {
        return 0;
    }
    // TSD slot 3 == __TSD_MACH_THREAD_SELF (see N00B_TSD_SLOT_MACH_THREAD_SELF
    // below; the macro is defined later in this file so the literal is used
    // here).
    return (int64_t)(uint32_t)tsd[3];
#elif defined(__APPLE__)
#error "n00b_os_thread_id: macOS non-arm64 needs a no-libc TSD read (x86-64: %gs-relative slot 3); pthread_threadid_np is banned (libc-removal mandate)."
#elif defined(_WIN32)
    return (int64_t)GetCurrentThreadId();
#else
#error "n00b_os_thread_id: add an OS thread-id primitive for this platform"
#endif
}

// Worker-side 64-bit exit-code stash (WP-3a, D-032 Q2 / D-033).  STASH-ONLY:
// store the code into the calling worker's own struct and return — this does
// NOT terminate the worker mid-fn (no setjmp/longjmp early-exit harness; the
// launcher publishes the stashed value on the normal fn()-return path).  A
// caller that does not resolve via n00b_thread_self() (the main thread, a
// foreign thread) is a no-op.  Framed is fine here: this is not on the
// n00b_thread_self() instrumentation path (D-019).
void
n00b_thread_exit(uint64_t code)
{
    n00b_thread_t *self = n00b_thread_self();
    if (self == nullptr) {
        return;
    }
    n00b_atomic_store(&self->exit_code, code);
}

// Read a thread's published 64-bit exit code.  Meaningful only after a
// successful n00b_thread_join (the worker settles exit_code before the
// join_futex publish-then-wake; see n00b_thread_launcher).  Distinct from the
// `void *` n00b_thread_join return (D-032 Q2).
uint64_t
n00b_thread_exit_code(n00b_thread_t *thread)
{
    if (thread == nullptr) {
        return 0;
    }
    return n00b_atomic_load(&thread->exit_code);
}

// Lock-free-stack ABA tag.  Doxygen lives on the declaration in
// include/adt/llstack.h; this is the implementation.  Layout: high 16 bits =
// thread slot (live-unique, so two threads never collide), low 48 bits = the
// thread's own monotonic counter (advances every op so a thread's own pop+push
// can't recreate a prior tag).  Per-thread (NOT per-CPU) — a per-CPU counter
// races under userspace migration with no rseq on macOS (the reason D-003
// retired the per-processor STW plan); a thread-local counter has no such race
// and needs no atomic.
uint64_t
_n00b_aba_tag(void)
{
    n00b_thread_t *self = n00b_thread_self();

    if (self != nullptr) {
        // Bootstrap window: n00b_thread_self() returns &_n00b_bootstrap_thread
        // before the main slot is published.  That stage is single-threaded, so
        // the non-atomic ++ on the bootstrap struct's aba_ctr is safe.
        uint64_t ctr = ++self->aba_ctr;
        return ((uint64_t)((uint32_t)self->id_info.parts.id & 0xffff) << 48)
             | (ctr & 0x0000ffffffffffffULL);
    }

    // Foreign/unregistered thread (no n00b_thread_self()): fall back to a
    // process-global monotonic counter, stamped 0xffff in the high 16 bits so
    // it cannot collide with a real thread's tag (real slots are < max_threads
    // << 0xffff).  Worst case (collision if max_threads ever reached 0xffff)
    // only degrades ABA detection to probabilistic for that thread — no worse
    // than the random guard this replaces.
    static _Atomic uint64_t n00b_foreign_aba_ctr = 0;
    uint64_t                ctr = n00b_atomic_add(&n00b_foreign_aba_ctr, 1);
    return (0xffffULL << 48) | (ctr & 0x0000ffffffffffffULL);
}

static uint32_t
n00b_thread_slot_acquire(n00b_runtime_t *rt, n00b_thread_t *ptr)
{
    for (;;) {
        uint32_t candidate = n00b_atomic_add(&rt->next_thread_slot, 1)
                             % rt->max_threads;
        if (candidate == N00B_MAIN_THREAD_SLOT
            && n00b_atomic_load(&rt->startup_complete)) {
            continue;
        }
        n00b_thread_t *expected = nullptr;
        if (n00b_cas(&rt->threads[candidate].thread, &expected, ptr)) {
            return candidate;
        }
    }

    __builtin_unreachable();
}

void
n00b_thread_init() _kargs
{
    n00b_runtime_t *runtime            = n00b_get_runtime();
    uint32_t acquired_slot             = 0;
    struct n00b_callstack_t *callstack = nullptr;
    uint32_t os_thread_port            = 0;
    // FOREIGN threads (no n00b callstack) must supply their own stack bounds —
    // the runtime does NOT discover them (no libc/pthread, and Mach's VM region
    // is too coarse to bound the live stack).  The embedding app knows its
    // stack; it passes [foreign_stack_low, foreign_stack_high).  Omitted (both
    // null) => this thread's C stack is NOT a GC root source (not scanned); such
    // a thread must self-register any roots.  A foreign thread MUST explicitly
    // n00b_thread_destroy to drop the registration.
    void    *foreign_stack_low         = nullptr;
    void    *foreign_stack_high        = nullptr;
}
{
    // WP-001: a thread's WHOLE init is critical execution.  Hold the single STW
    // gate across all of it — slot acquire, stack registration (which locks the
    // mmap registry, re-acquiring the gate reentrantly — intended), the first
    // GC-visible allocation, and slot publication.  A stop-the-world initiator
    // must acquire this gate before it suspends anyone, so it can never freeze a
    // thread that is mid-init (a participant it could neither safely scan nor
    // cleanly suspend).  Keyed on the OS thread id, so it works even though
    // n00b_thread_self() is not yet resolvable here.  Released at the very end,
    // once the thread is fully registered + suspendable.
    n00b_rw_read_lock(&runtime->critical_execution);

    // n00b_thread_self() must be resolvable for the calling thread BEFORE the first
    // GC-pushing allocation below (the codegen wraps every alloc in a GC
    // stack-frame push that calls n00b_thread_self()).  The main thread is covered by
    // the bootstrap struct (its main-slot bounds are still unset, so n00b_thread_self()
    // returns the bootstrap).  A worker, however, runs concurrently with an
    // already-registered main thread, so the bootstrap path no longer
    // applies to it; it must resolve via the per-thread bounds scan.  So:
    //
    //   1. acquire/confirm the slot and publish this thread's stack bounds
    //      and an init-time self pointer into its record FIRST, using an
    //      init-scoped n00b_thread_t that lives on the C stack;
    //   2. allocate the permanent struct from the GC-visible user_pool
    //      (WP-3a / D-034; now n00b_thread_self() resolves —
    //      main -> bootstrap, worker -> &init_self via the bounds scan);
    //   3. copy the init-time state into the permanent struct and repoint
    //      the slot at it.
    //
    // The init-scoped struct never escapes init: GC frames hold C-stack
    // addresses (not the thread struct), and gc_stack_top is copied into
    // the permanent struct at the handoff.
    n00b_thread_t init_self = {};
    // Only the MAIN thread continues the bootstrap struct's frame chain: it
    // ran on _n00b_bootstrap_thread (n00b_thread_self() -> bootstrap) during
    // early n00b_init before attaching here, so its pre-attach frames live on
    // bootstrap.gc_stack_top and must carry over.  A WORKER or FOREIGN
    // (libdispatch/XPC) thread never used the bootstrap struct as its self —
    // its pre-attach prologue pushes were null-self no-ops (see
    // n00b_gc_stack_push) — so it must start with an EMPTY frame chain.
    // Inheriting bootstrap.gc_stack_top for such a thread would root its chain
    // in MAIN's stale stack frames, which then faults when the chain is walked
    // (n00b_gc_stack_pop / the GC stack-root scan).  The main thread is the
    // first to init before runtime startup completes.  After startup, a daemon
    // may detach the initial thread and later attach a foreign dispatch thread;
    // that must not become "main" just because live_threads is temporarily 0.
    bool is_main              = !n00b_atomic_load(&runtime->startup_complete)
                                && n00b_atomic_load(&runtime->live_threads) == 0;
    init_self.gc_stack_top    = is_main ? _n00b_bootstrap_thread.gc_stack_top
                                        : nullptr;
    init_self.gc_stack_policy = _n00b_bootstrap_thread.gc_stack_policy;
    // Record the worker's callstack on the init-scoped struct BEFORE the
    // first allocation: n00b_thread_self()'s worker-masking branch back-verifies the
    // resolved thread's callstack->region_start against the masked SP base,
    // so a worker must carry its callstack from the very first n00b_thread_self() (the
    // GC-stack push around the permanent-struct alloc below).  Null for the
    // main thread, which resolves via the range check instead.
    init_self.callstack = (n00b_callstack_t *)callstack;

    // ORDERING (WP-001 Phase 2): a WORKER initialises concurrently with a live
    // runtime, so the instant it is published into rt->threads[] (the
    // slot-acquire below) a stop-the-world pass on another thread can observe
    // it.  For the pure-preemptive STW (no cooperative fallback) the worker must
    // therefore already be SUSPENDABLE (a real OS control handle) and SCANNABLE
    // (stack map + stack top) BEFORE it is published — otherwise STW would find
    // a participant it can neither suspend nor safely scan, and the worker's
    // first allocation (the permanent struct below) could run while the world is
    // "stopped".  Everything needed is knowable here, pre-publication:
    //   - stack_map / stack_base: the worker's callstack region (already
    //     registered as n00b_mmap_stack by n00b_callstack_alloc);
    //   - stack_top: captured now;
    //   - control handle: macOS uses the thread_create port the spawner passed
    //     in via os_thread_port (kept identical to the reaper's death-edge
    //     port); Linux/Windows read the running thread's own tid here.
    // The rec->stack_lo/hi pair (used ONLY by n00b_thread_self() resolution, not
    // by the GC scan) is still published by n00b_capture_stack_base after the
    // slot is known, before the first alloc.  The MAIN thread needs none of this
    // ordering: it initialises while live_threads == 0 (single-threaded), so no
    // concurrent STW can observe it mid-init.
    if (callstack != nullptr) {
        n00b_callstack_t *cs = (n00b_callstack_t *)callstack;
        init_self.stack_map  = cs->stack_map;
        init_self.stack_base = (void *)cs->stack_high;
        n00b_capture_stack_top(&init_self);
        // macOS: the spawner's thread_create port.  Also record the raw OS
        // thread id on every platform so STW can identify the initiator even
        // when n00b_thread_self() cannot resolve a foreign thread.
        init_self.os_thread_port = os_thread_port;
#if defined(__APPLE__)
        init_self.os_tid = (uint32_t)n00b_os_thread_id();
#elif defined(__linux__)
        init_self.os_tid = (uint32_t)_n00b_raw_linux_syscall1(SYS_gettid, 0);
#elif defined(_WIN32)
        init_self.os_tid = (uint32_t)GetCurrentThreadId();
#endif
    }

    if (!acquired_slot) {
        acquired_slot = n00b_thread_slot_acquire(runtime, &init_self);
    }
    else {
        // Pre-acquired slot (worker launcher): the slot holds a placeholder;
        // replace it with the init-scoped struct.
        n00b_atomic_store(&runtime->threads[acquired_slot].thread,
                          &init_self);
    }

    n00b_thread_record_t *rec = &runtime->threads[acquired_slot];
    uint32_t              gen = rec->generation++;

    // Slots are reused without re-zeroing; the pool page-gate depth is
    // balanced by construction but must not inherit a prior occupant's value.
    rec->pool_gate_depth = 0;

    init_self.record                   = rec;
    init_self.id_info.parts.id         = (int32_t)acquired_slot;
    init_self.id_info.parts.generation = (int32_t)gen;

    // Foreign (libdispatch/XPC) thread: capture its OS control handle — its
    // suspend identity — NOW, before n00b_capture_stack_base registers its
    // stack (that registration locks the mmap registry) and before its
    // live-slot bit is published.  A foreign thread becomes collector-visible
    // the moment its bit is set; it MUST already be suspendable by then, or a
    // collection landing in that window spins forever trying to suspend a
    // handle-less thread.  Workers carry the launcher's port (set in the
    // callstack block above); main captures below while still single-threaded.
    // macOS: the +1 mach_thread_self() send right is dropped by the foreign
    // reaper (this capture simply moved earlier than the permanent struct).
    if (!is_main && callstack == nullptr) {
#if defined(__APPLE__)
        init_self.os_thread_port = (uint32_t)mach_thread_self();
        init_self.os_tid         = (uint32_t)n00b_os_thread_id();
#elif defined(__linux__)
        init_self.os_tid = (uint32_t)_n00b_raw_linux_syscall1(SYS_gettid, 0);
#elif defined(_WIN32)
        init_self.os_tid = (uint32_t)GetCurrentThreadId();
#endif
    }

    // Publish bounds + the init self pointer so n00b_thread_self() resolves for this
    // thread during the permanent-struct allocation below.  capture_base
    // writes rec->stack_lo/hi (stack_hi first, stack_lo last as the gate) and,
    // for a foreign thread, publishes the live-slot bit before it registers its
    // stack (so n00b_thread_self() resolves for that registration's lock).
    n00b_capture_stack_base(&init_self, runtime, foreign_stack_low, foreign_stack_high);
    n00b_capture_stack_top(&init_self);

    // Publish this slot in the live-slot bitmap AFTER its bounds are set
    // (capture_stack_base above), so n00b_thread_self()'s bounds scan only
    // ever sees a set bit paired with a valid [stack_lo, stack_hi).  The bit
    // is cleared first in n00b_thread_exit, before the bounds are torn down.
    n00b_atomic_or(&runtime->live_slot_bits[acquired_slot >> 6],
                   (uint64_t)1 << (acquired_slot & 63u));

    // WP-001: n00b_thread_self() now resolves (with a record); adopt the
    // record-less gate read hold taken at the top of init into a read-log
    // record.  Without this, the first GC-visible allocation below re-acquires
    // the gate, fails to recognize its own outstanding hold (no record), and
    // blocks behind a draining stop-the-world writer that is itself waiting for
    // this very hold to drop — deadlock.  See n00b_rw_adopt_read_hold.
    n00b_rw_adopt_read_hold(&runtime->critical_execution, n00b_thread_self());

    // Now n00b_thread_self() resolves to &init_self; allocate the permanent
    // struct from the GC-VISIBLE, non-moving runtime_obj_pool (WP-3a / D-034;
    // renamed from user_pool at the WP-close rebase to avoid colliding with
    // upstream's hidden leak-tracking user_pool — D-034/D-039) — NOT the hidden
    // system_pool.  The GC owns the struct's lifetime: reachable -> kept,
    // unreferenced -> reclaimed (once the assumed pool-collection capability
    // lands).  Being a pool, runtime_obj_pool is non-moving, so this address
    // stays valid for rt->threads[].thread and n00b_thread_self().
    n00b_allocator_t *up_alloc = (n00b_allocator_t *)&runtime->runtime_obj_pool;
    n00b_thread_t    *self     = n00b_alloc_with_opts(
        n00b_thread_t,
        &(n00b_alloc_opts_t){.allocator = up_alloc});

    *self = init_self;
    // Re-pick up gc_stack_top in case the allocation pushed/popped frames
    // that mutated it (balanced, so it should equal init_self's, but read
    // through n00b_thread_self() to be exact).
    self->gc_stack_top = init_self.gc_stack_top;

    // Foreign-thread reclamation (D-034 extension): a NOT-main, NO-callstack
    // thread is a FOREIGN (libdispatch/XPC) thread that never calls
    // n00b_thread_destroy, so the slot-scanning foreign reaper
    // (_n00b_reap_foreign_sweep) needs its Mach thread port to detect OS death
    // and reclaim the slot.  That port is now captured EARLY (into init_self,
    // before the live-slot bit is published — see above) so the thread is
    // suspendable the instant it becomes collector-visible; it rides onto
    // `self` via the *self = init_self copy.  The +1 mach_thread_self() send
    // right is dropped by the reaper via mach_port_deallocate.

    // WP-001 / WP-4 (D-040): the MAIN thread must be preemptible like every
    // other thread — a worker that triggers GC has to be able to stop main and
    // capture its registers.  So main carries a real OS control handle, just as
    // a launched worker does (n00b_thread_launcher sets these for workers).
    // main never goes through the launcher, so set them here, on the permanent
    // struct, before it is published.  main is never reaped, so the macOS +1
    // send right from mach_thread_self() is simply held for the process
    // lifetime (no reaper ever deallocates it — every reaper skips main).
    if (is_main) {
#if defined(__APPLE__)
        self->os_thread_port = (uint32_t)mach_thread_self();
        self->os_tid         = (uint32_t)n00b_os_thread_id();
#elif defined(__linux__)
        self->os_tid = (uint32_t)_n00b_raw_linux_syscall1(SYS_gettid, 0);
#elif defined(_WIN32)
        self->os_tid = (uint32_t)GetCurrentThreadId();
#endif
    }

    // Repoint the slot at the permanent struct.  After this store, n00b_thread_self()
    // resolves (main: range check; worker: bounds scan) to `self`.
    n00b_atomic_store(&rec->thread, self);

    n00b_atomic_add(&runtime->live_threads, 1);
    n00b_futex_wake((n00b_futex_t *)&rec->thread, true);

    // Fully registered + suspendable: end the critical-execution window.
    n00b_rw_unlock(&runtime->critical_execution);
}

#if defined(__APPLE__)
// Reclaim-on-attach (2026-06-02): make foreign-thread identity sound under
// libdispatch stack reuse.  EVIDENCE (this session): a foreign (libdispatch/XPC)
// thread that REUSES a dead thread's stack resolves n00b_thread_self() to that
// dead thread's STALE record — its SP falls inside the dead thread's still-
// advertised [stack_lo,stack_hi) (dead foreign threads never call
// n00b_thread_destroy, so their slot keeps advertising bounds + the live bit).
// Running n00b code while WEARING a dead identity is what let the GC reaper pull
// the record out from under an in-flight collect (the gc.c:213 self()-null
// crash).  Fix: at every foreign entry, BEFORE any other n00b work, detect the
// stale alias by Mach-port identity and, if found, DETACH from the stale record
// (clear its live bit + stack_lo gate so the bounds scan stops resolving our SP
// to it) and attach a FRESH slot this thread owns.  The stale record then has no
// live aliaser and is safe for the under-STW reaper to reclaim.  Returns the
// thread's own (post-attach) record.  Idempotent: once a foreign thread owns its
// record (port matches), this is a cheap no-op + return.
n00b_thread_t *
n00b_thread_attach_foreign() _kargs
{
    void *foreign_stack_low  = nullptr;
    void *foreign_stack_high = nullptr;
}
{
    n00b_runtime_t *rt = n00b_get_runtime();
    if (rt == nullptr || rt->threads == nullptr || rt->live_slot_bits == nullptr) {
        n00b_thread_init(.foreign_stack_low  = foreign_stack_low,
                         .foreign_stack_high = foreign_stack_high);
        return n00b_thread_self();
    }

    n00b_thread_t *self = n00b_thread_self();

    if (self != nullptr && self->record != nullptr) {
        // n00b WORKERS (callstack != null) resolve via their callstack region
        // and are not aliasable by a foreign libdispatch stack.
        if (self->callstack != nullptr) {
            return self;
        }

        // Main and foreign records both carry a Mach control port.  Accept the
        // identity only when that port is the current thread's port.  This
        // catches stale main-slot aliases after dispatch_main() as well as
        // ordinary dead-foreign stack reuse.
        mach_port_t mine = mach_thread_self();
        bool        ours = (self->os_thread_port == (uint32_t)mine);
        (void)mach_port_deallocate(mach_task_self(), mine);
        if (ours) {
            return self;
        }
        // Stale alias.  Detach from the dead thread's record so n00b_thread_self()
        // stops resolving our SP to it: clear the live-slot bit, then null the
        // stack_lo release gate (a null gate makes the bounds scan skip the slot
        // even if it reads the bit before the clear is visible).  Lock-free
        // atomics; the record's struct / port / mmap node are left intact for
        // the under-STW reaper, which can now reclaim it with no live aliaser.
        uint32_t s = (uint32_t)self->id_info.parts.id;
        n00b_atomic_and(&rt->live_slot_bits[s >> 6],
                        ~((uint64_t)1 << (s & 63u)));
        n00b_atomic_store(&rt->threads[s].stack_lo, (void *)nullptr);
        // fall through to a fresh attach below.
    }

    n00b_thread_init(.foreign_stack_low  = foreign_stack_low,
                     .foreign_stack_high = foreign_stack_high);
    return n00b_thread_self();
}
#endif

static void
n00b_release_locks_on_thread_exit(n00b_thread_record_t *rec)
{
    // Walk exclusive locks and force-release each one.
    n00b_lock_base_t *lock = n00b_atomic_load(&rec->exclusive_locks);

    while (lock) {
        n00b_lock_base_t      *next = n00b_atomic_load(&lock->next_thread_lock);
        n00b_core_lock_info_t  info = n00b_atomic_load(&lock->data);

        info.owner   = N00B_NO_OWNER;
        info.nesting = 0;
        atomic_store(&lock->data, info);
        atomic_store(&lock->prev_thread_lock, nullptr);
        atomic_store(&lock->next_thread_lock, nullptr);

        // If this is a mutex or rwlock, release the futex.
        if (info.type == N00B_NLT_MUTEX) {
            n00b_mutex_t *m = (n00b_mutex_t *)lock;
            atomic_store(&m->futex, 0);
            if (n00b_atomic_load(&m->should_wake)) {
                n00b_futex_wake(&m->futex, true);
            }
        }
        else if (info.type == N00B_NLT_RW) {
            n00b_rwlock_t *rw = (n00b_rwlock_t *)lock;
            n00b_atomic_and(&rw->futex, ~N00B_RW_W_LOCK);
            n00b_futex_wake(&rw->futex, true);
        }
        else if (info.type == N00B_NLT_SPIN) {
            // Non-parking spinlock: just clear the lock word.  No waiter to
            // wake — spinners re-test it directly.
            n00b_spin_lock_t *s = (n00b_spin_lock_t *)lock;
            atomic_store(&s->spin, 0);
        }

        lock = next;
    }
    n00b_atomic_store(&rec->exclusive_locks, nullptr);

    // Walk read locks and force-release each one — INCLUDING the STW gate
    // (critical_execution).  This is the catch-all that drops every read lock a
    // thread still holds at teardown (reaper at thread.c:1932, and the destroy
    // path which calls us mid-teardown).  The gate MUST be dropped here so a
    // thread torn down while holding it does not leak a reader count that the
    // collector's write lock then waits on forever.  n00b_thread_destroy relies
    // on this to drop its own gate hold (it does NOT release the gate again
    // afterwards).
    n00b_thread_read_log_t *rlog = n00b_atomic_load(&rec->read_locks);

    while (rlog) {
        n00b_thread_read_log_t *next = rlog->next_entry;
        n00b_rwlock_t          *rw   = rlog->obj;

        if (rw && rlog->level > 0) {
            // Drop one futex unit for this record.  A read-log record holds
            // exactly ONE futex unit regardless of its reentrancy level (nested
            // re-acquires bump only the record level, never the futex), so drop
            // one unit per record.  The helper guards against underflow (so a
            // unit already dropped by another teardown path cannot wrap the
            // count and latch W_LOCK) and wakes a draining stop-the-world
            // initiator once the count reaches zero.
            _n00b_rw_drop_reader_unit(rw);
        }

        rlog = next;
    }
    n00b_atomic_store(&rec->read_locks, nullptr);
    n00b_atomic_store(&rec->log_alloc_cache, nullptr);
}

void
n00b_thread_destroy(void)
{
    n00b_thread_t *self = n00b_thread_self();
    if (self == nullptr) {
        return;
    }

    n00b_epoch_thread_exit(self);

    // WP-001: a thread's WHOLE destroy is critical execution.  Hold the single
    // STW gate across all of it.  Teardown nulls rec->thread and frees the
    // stack registration, after which n00b_thread_self() no longer resolves —
    // but the gate is keyed on the OS thread id, so it stays valid throughout.
    // Holding it means a stop-the-world initiator (which must acquire the gate
    // before suspending anyone) can never freeze a thread mid-teardown, so the
    // collector never scans a stack being dismantled.  The nested mmap
    // unregister below re-acquires the gate reentrantly — intended.
    n00b_runtime_t *destroy_gate_rt = n00b_get_runtime();
    n00b_rw_read_lock(&destroy_gate_rt->critical_execution);

    n00b_thread_record_t *rec = self->record;

    // Destroy this thread's transient-scratch pool (n00b_thread_scratch_pool),
    // if it was ever created, while self is still fully resolvable.  It is a
    // hidden, non-GC pool holding only raw buffers (no locks), so destroy just
    // unmaps its pages; mmap-tree mutation nests the critical_execution gate
    // held above reentrantly, like the stack unregister below.
    if (self->scratch_pool != nullptr) {
        n00b_allocator_t *dead_scratch = (n00b_allocator_t *)self->scratch_pool;
        self->scratch_pool             = nullptr;
        n00b_allocator_destroy(dead_scratch);
    }

    // n00b_release_locks_on_thread_exit (below, in the rec branch) force-drops
    // this thread's gate read lock (it is recorded in rec->read_locks via the
    // record-path acquire above).  Track that so we do NOT release the gate a
    // second time at the end; only the no-record case (rec == nullptr, the gate
    // taken via the record-less path) needs the explicit release.
    bool gate_dropped_by_release_locks = false;

    if (rec) {
        // If this thread is on a CV's waiters list, remove it.
        n00b_condition_t *cv = rec->cv_info.current_cv;
        if (cv) {
            (void)n00b_list_remove_all(cv->waiters, self);
            rec->cv_info.current_cv = nullptr;
        }

        // Unregister this thread's stack from the mmap tree NOW, while the
        // thread is still fully self-resolvable (live bit set, bounds + record
        // intact).  The registry lock (the re-entrant spinlock) needs
        // n00b_thread_self(); the identity teardown below clears the live-slot
        // bit and rec->thread, after which self() returns null and the lock
        // would null-deref.  The whole teardown runs under critical_execution
        // (held at the top), so this registry mutation just nests the gate
        // reentrantly — no stop-the-world can race it.
        //
        // Only a thread that OWNS its stack registration unregisters it: a raw
        // WORKER's self->stack_map aliases its callstack's registration
        // (cs->stack_map), owned by the callstack reclamation path the reaper
        // drives at OS-confirmed death — unregistering it here too would
        // double-delete the node and corrupt the tree.  A worker carries a
        // callstack; skip it (the reaper reclaims).  Main + FOREIGN threads
        // carry no callstack and own their registration, so they unregister.
        n00b_runtime_t *destroy_rt = n00b_get_runtime();
        if (destroy_rt != nullptr && self->stack_map != nullptr
            && self->callstack == nullptr) {
            // Null stack_map FIRST, then unregister (which frees the registry
            // object).  The collector reads t->stack_map for the conservative
            // stack scan and skips a null one; clearing it before the free
            // means it never observes a dangling (freed) pointer — it sees the
            // valid map (still-mapped stack) or null (skip), never freed.
            void *stack_start  = (void *)self->stack_map->start;
            self->stack_map    = nullptr;
            n00b_mmap_unregister(stack_start);
        }

        n00b_release_locks_on_thread_exit(rec);
        gate_dropped_by_release_locks = true; // it dropped our gate read hold

        // Retire this worker's stack-bounds advertisement BEFORE clearing
        // the slot.  n00b_thread_self()'s worker bounds-scan matches an SP
        // against every slot's published [stack_lo, stack_hi); once this
        // worker exits its callstack is freed and its address range can be
        // handed to a LATER worker's callstack.  If the dead slot kept
        // advertising that range (with rec->thread now null), the scan would
        // match the dead slot first and resolve n00b_thread_self() to null for the new
        // worker — crashing it (n00b_capture_stack_top on a null self).
        // Retire this slot from the live-slot bitmap FIRST, before tearing
        // down the bounds/thread the scan reads.  The bit is the authoritative
        // "this slot's bounds are valid" gate, so clearing it here makes
        // n00b_thread_self()'s bounds scan stop matching this slot the moment
        // teardown begins — preventing a recycled stack range from resolving
        // to this dead slot.  This covers FOREIGN threads too, whose bounds
        // are NOT cleared by the callstack-only stack_lo/hi clear below.
        {
            n00b_runtime_t *exit_rt = n00b_get_runtime();
            if (exit_rt != nullptr && exit_rt->live_slot_bits != nullptr) {
                uint32_t exit_slot = (uint32_t)self->id_info.parts.id;
                n00b_atomic_and(&exit_rt->live_slot_bits[exit_slot >> 6],
                                ~((uint64_t)1 << (exit_slot & 63u)));
            }
        }

        // Clear stack_lo first (it is the release gate the scan loads first;
        // a null gate makes the scan skip this slot), then stack_hi.  This is
        // required for every detached identity: raw workers, foreign threads,
        // and the initial thread before a daemon enters dispatch_main().
        n00b_atomic_store(&rec->stack_lo, (void *)nullptr);
        n00b_atomic_store(&rec->stack_hi, (void *)nullptr);

        // Exclude this thread from the collector's scan set (rec->thread is the
        // atomic n00b_scan_thread_stacks reads).  We hold critical_execution, so
        // no stop-the-world can be in progress right now; clearing rec->thread
        // ensures that the NEXT collection ignores this slot rather than scanning
        // a stack this thread is dismantling / about to munmap (TOCTOU).  Its
        // lock chain was already emptied by n00b_release_locks_on_thread_exit, so
        // skipping it loses no root.  (No cooperative SUSPEND self-mark anymore —
        // the gate, not a self_lock bit, is what keeps the collector off us.)
        n00b_atomic_store(&rec->thread, nullptr);
    }

    if (self->memperm_pipe.ready) {
#ifdef _WIN32
        _close(self->memperm_pipe.fds[0]);
        _close(self->memperm_pipe.fds[1]);
#elif defined(__linux__)
        (void)_n00b_raw_linux_syscall1(SYS_close, self->memperm_pipe.fds[0]);
        (void)_n00b_raw_linux_syscall1(SYS_close, self->memperm_pipe.fds[1]);
#else
        close(self->memperm_pipe.fds[0]);
        close(self->memperm_pipe.fds[1]);
#endif
    }

#if defined(__APPLE__)
    if (self->callstack == nullptr && self->os_thread_port != 0) {
        (void)mach_port_deallocate(mach_task_self(),
                                   (mach_port_name_t)self->os_thread_port);
        self->os_thread_port = 0;
    }
#endif

    n00b_runtime_t *rt = n00b_get_runtime();
    if (rt) {
        // The stack-region unregister happens earlier (top of teardown, while
        // the thread is still self-resolvable for the registry lock).
        n00b_atomic_add(&rt->live_threads, -1);
        n00b_futex_wake((n00b_futex_t *)&rt->live_threads, true);
    }

    // End the critical-execution window.  If we had a record, the gate read was
    // already force-dropped by n00b_release_locks_on_thread_exit above; release
    // it explicitly only in the record-less case (where that path did not run).
    if (!gate_dropped_by_release_locks) {
        n00b_rw_unlock(&destroy_gate_rt->critical_execution);
    }
}

bool
n00b_current_thread_stack_contains(void *ptr)
{
    if (ptr == nullptr) {
        return false;
    }

    uintptr_t      p      = (uintptr_t)ptr;
    n00b_thread_t *thread = n00b_thread_self();

    if (thread == nullptr) {
        return false;
    }

    // The registered stack region (n00b_mmap_stack) is the authoritative
    // span for the calling thread: for the main thread it is the
    // OS-native bounds captured in n00b_capture_stack_base (mach_vm on
    // macOS, NT_TIB on Windows, rlimit+environ on Linux); for a worker
    // (Phase 3) it is the n00b callstack region.  No pthread query is
    // needed — the bounds were discovered OS-natively at registration.
    n00b_mmap_info_t *map = thread->stack_map;
    if (map != nullptr && p >= map->start && p < map->end) {
        return true;
    }

    // Fall back to the main-thread kernel-stack bounds stored in the
    // record (same source the n00b_thread_self() range check uses), in case the
    // probed address sits in the kernel stack mapping outside the
    // narrower registered range.
    n00b_thread_record_t *rec = thread->record;
    if (rec != nullptr && rec->stack_lo != nullptr) {
        uintptr_t lo = (uintptr_t)rec->stack_lo;
        uintptr_t hi = (uintptr_t)rec->stack_hi;
        if (p >= lo && p < hi) {
            return true;
        }
    }

    return false;
}

void
n00b_capture_stack_base(n00b_thread_t *thread,
                        n00b_runtime_t *runtime,
                        void           *foreign_stack_low,
                        void           *foreign_stack_high)
{
    size_t size;
    char  *highest;
    char  *lowest;

    // Raw worker (WP-001 Phase 3): the thread runs on an n00b callstack,
    // not a pthread-managed or kernel-main stack.  Its bounds are exactly
    // the callstack's usable span — no OS stack query needed — and the
    // region is already registered as n00b_mmap_stack by
    // n00b_callstack_alloc, so we publish the bounds + reuse that record
    // rather than re-registering.  (macOS/Linux run on `cs`; on Windows
    // Win32 owns the running stack and `callstack` is left null, so this
    // branch is skipped and the platform path below applies.)
    if (thread->callstack != nullptr) {
        n00b_callstack_t *cs = thread->callstack;
        lowest               = (char *)cs->stack_low;
        highest              = (char *)cs->stack_high;

        thread->stack_base = highest;
        if (thread->record != nullptr) {
            n00b_atomic_store(&thread->record->stack_hi, (void *)highest);
            n00b_atomic_store(&thread->record->stack_lo, (void *)lowest);
        }
        thread->stack_map = cs->stack_map;
        // Cache the guard band flat on the thread so the WP-3b crash handler
        // classifies a stack-overflow fault by a lock-free pointer-range
        // compare (async-signal-safe).  Main thread (no callstack) leaves these
        // null — its overflow is the OS-native stack guard, not an n00b band.
        // Store hi first, lo last (lo is the gate the crash handler checks
        // first), with release semantics so the handler's acquire load sees a
        // consistent pair (matches the stack_lo/stack_hi discipline).
        n00b_atomic_store(&thread->guard_hi,
                          (void *)((char *)cs->guard_start + cs->guard_size));
        n00b_atomic_store(&thread->guard_lo, cs->guard_start);
        return;
    }

#ifdef _WIN32
    // On Windows, foreign service/host threads can provide the full reserved
    // stack range.  Prefer it over TEB->StackLimit, which is only the current
    // committed low page and can move downward after large frames are entered.
    (void)runtime;
    if (foreign_stack_low != nullptr && foreign_stack_high != nullptr
        && (char *)foreign_stack_high > (char *)foreign_stack_low) {
        lowest  = (char *)foreign_stack_low;
        highest = (char *)foreign_stack_high;
        size    = (size_t)(highest - lowest);
    }
    else {
        NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
        highest = (char *)tib->StackBase;
        lowest  = (char *)tib->StackLimit;
        size    = highest - lowest;
    }
#else
    if (!n00b_atomic_load(&runtime->live_threads)) {
#ifdef __APPLE__
        // pthread_get_stackaddr_np and the env-walking heuristic both
        // miss the main thread's true stack top on macOS — pthread
        // reports the pthread-managed region (below where the kernel
        // placed argv/envp and main()'s frame), and env-walking only
        // covers the env-string area, which isn't always the
        // highest-addressed page in the stack mapping.  Either way,
        // any local in main's frame can end up *above* the registered
        // stack_map range, and the GC's stack-root scan misses it.
        // The mach_vm region containing a known stack address IS the
        // full stack, so use that.
        // Pick an anchor that's actually inside the main thread's
        // real stack region.  On macOS the kernel-set-up main stack
        // is *above* what pthread_get_stackaddr_np reports, and also
        // above where the argv/envp strings live, so a local in this
        // function (in the pthread region) and argv[0] / envp[0] (in
        // the strings region) both miss it.  The argv array itself
        // (`runtime->argv.data` — the C `argv` pointer value passed to
        // main) lives at the very top of main's actual stack frame
        // area, so that's the anchor that gets mach_vm_region_recurse
        // to return the right region.
        char anchor;
        char *anchor_p = (char *)runtime->argv.data;
        if (!anchor_p) {
            anchor_p = (char *)&anchor;
        }
        mach_vm_address_t region_addr = (mach_vm_address_t)anchor_p;
        mach_vm_size_t    region_size = 0;
        natural_t                       depth = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t          info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t                   kr;
        kr = mach_vm_region_recurse(mach_task_self(), &region_addr,
                                    &region_size, &depth,
                                    (vm_region_recurse_info_t)&info,
                                    &info_count);
        (void)0;
        // mach_vm_region_recurse is the OS-native main-stack discovery on
        // macOS and is retained as-is (D-009); on the (not-expected)
        // failure path we leave the bounds zeroed rather than fall back to
        // a pthread query, keeping main-thread discovery fully pthread-free.
        if (kr == KERN_SUCCESS) {
            lowest  = (char *)(uintptr_t)region_addr;
            highest = lowest + region_size;
            size    = region_size;
        }
        else {
            lowest  = nullptr;
            highest = nullptr;
            size    = 0;
        }
#elif defined(__linux__)
        char *mapped_low;
        char *mapped_high;
        char  anchor;

        if (n00b_linux_mapping_bounds_for(&anchor, &mapped_low, &mapped_high)) {
            highest = mapped_high;
            lowest  = mapped_low;
            size    = (size_t)(highest - lowest);

            struct rlimit rlimit;
            if (getrlimit(RLIMIT_STACK, &rlimit) == 0
                && rlimit.rlim_cur != RLIM_INFINITY
                && rlimit.rlim_cur > size) {
                lowest = highest - rlimit.rlim_cur;
                size   = rlimit.rlim_cur;
            }
        }
        else {
            struct rlimit rlimit;
            getrlimit(RLIMIT_STACK, &rlimit);
            size = rlimit.rlim_cur;
            extern char **environ;
            char        **env = environ;
            // Stop at the top string.
            while (env[1]) {
                env++;
            }
            // Find the very end, then align it.
            char *p = *env + 1;
            highest = p + strlen(p) + 1 + sizeof(void *);
            highest = (char *)(((uint64_t)highest) & ~(sizeof(void *) - 1));
            lowest  = highest - size;
        }
#else
        struct rlimit rlimit;
        getrlimit(RLIMIT_STACK, &rlimit);
        size = rlimit.rlim_cur;
        extern char **environ;
        char        **env = environ;
        // Stop at the top string.
        while (env[1]) {
            env++;
        }
        // Find the very end, then align it.
        char *p = *env + 1;
        highest = p + strlen(p) + 1 + sizeof(void *);
        highest = (char *)(((uint64_t)highest) & ~(sizeof(void *) - 1));
        lowest  = highest - size;
#endif
    }
    else {
        // FOREIGN thread (non-main, no n00b callstack): a raw pthread /
        // libdispatch / XPC worker the embedding app attached via
        // n00b_thread_init.  The runtime does NOT discover its stack bounds —
        // there is no libc/pthread to ask (project mandate), and Mach's VM
        // region is too coarse to bound the live stack (it spans guard pages /
        // adjacent mappings, so a conservative scan walks off the committed
        // stack and faults).  The embedding app KNOWS its stack and passes
        // [foreign_stack_low, foreign_stack_high) explicitly; we register
        // exactly that.  If it passed nothing (both null) — or a degenerate
        // range — this thread's C stack is simply not a GC root source: bounds
        // stay zeroed (the register below is guarded), so it is never scanned.
        // Such a thread must self-register any roots and MUST explicitly
        // n00b_thread_destroy to drop its slot.
        if (foreign_stack_low != nullptr && foreign_stack_high != nullptr
            && (char *)foreign_stack_high > (char *)foreign_stack_low) {
            lowest  = (char *)foreign_stack_low;
            highest = (char *)foreign_stack_high;
            size    = (size_t)(highest - lowest);
        }
        else {
            lowest  = nullptr;
            highest = nullptr;
            size    = 0;
        }
    }
#endif
    (void)size; // consumed only to compute `highest` in the branches above.

    thread->stack_base = highest;

    // Publish the stack bounds into the thread record BEFORE the
    // mmap-tree registration (which allocates and therefore triggers a
    // GC-stack push that calls n00b_thread_self()): a worker resolves n00b_thread_self() via the
    // bounds scan, so its bounds must be visible before the first alloc.
    // stack_hi is written first, stack_lo last as the release gate (a
    // non-null stack_lo implies stack_hi is set), matching the load order
    // in n00b_thread_self().
    if (thread->record != nullptr) {
        n00b_atomic_store(&thread->record->stack_hi, (void *)highest);
        n00b_atomic_store(&thread->record->stack_lo, (void *)lowest);
    }

    // Publish the live-slot bit NOW — before the stack registration below locks
    // the mmap registry — so a foreign thread (which resolves n00b_thread_self()
    // via the live-slot scan, not a range check or callstack fast path) is
    // self-resolvable for that lock's owner/accounting.  Its OS control handle
    // was already captured in n00b_thread_init, so becoming collector-visible
    // here is safe (it is suspendable).  Bounds were published just above (the
    // bit's invariant: a set bit implies a valid [stack_lo, stack_hi)).
    // Idempotent with the (re)publish in n00b_thread_init.  Workers never reach
    // here (they early-return on their callstack region) and resolve via the
    // O(1) callstack fast path, so they need no early bit.
    if (thread->record != nullptr && runtime != nullptr
        && runtime->live_slot_bits != nullptr) {
        uint32_t slot = (uint32_t)thread->id_info.parts.id;
        n00b_atomic_or(&runtime->live_slot_bits[slot >> 6],
                       (uint64_t)1 << (slot & 63u));

        // WP-001: n00b_thread_self() now resolves (with a record).  The stack
        // registration just below re-acquires the STW gate (n00b_mmap_by_address
        // / n00b_mmap_register -> mmap_lock).  The thread already holds that gate
        // from the top of its init, but that outer hold was taken null-self
        // (before the TCB existed) and so carries NO read-log record.  Without
        // adopting it here, the nested mmap acquire fails to recognize its own
        // hold and blocks behind a draining stop-the-world writer that is itself
        // waiting for this very hold to drop — deadlock (observed for FOREIGN
        // threads, whose stack registration runs THIS branch, before the
        // adoption in n00b_thread_init proper).  Adopt now, before the nested
        // acquire.  Idempotent with the later n00b_thread_init adoption.
        n00b_rw_adopt_read_hold(&runtime->critical_execution, n00b_thread_self());
    }

    // Only register a real region.  Foreign-thread stack discovery can fail
    // (off-macOS, or a mach_vm error), leaving zeroed bounds; registering
    // those would trip n00b_mmap_register's (end > start) assertion.  With
    // bounds zeroed the thread's published stack_lo stays null, so the
    // n00b_thread_self() bounds scan simply skips its slot (resolves null)
    // rather than crashing — a degraded but safe outcome.
    if (highest > lowest) {
        // Reuse an existing node for this EXACT stack range if one is already
        // registered.  Foreign (libdispatch) threads reuse a small pool of OS
        // stacks, so a successor thread on the same stack would otherwise add a
        // DUPLICATE interval-tree node (the tree permits overlaps).  The foreign
        // reaper deliberately does NOT unregister stack nodes (it would be
        // ambiguous / could double-delete a node a live successor shares), so
        // duplicates would accumulate.  Reusing keeps exactly one node per
        // distinct stack range — bounded by the peak thread count.
        auto              existing = n00b_mmap_by_address(lowest);
        n00b_mmap_info_t *reuse    = nullptr;
        if (n00b_option_is_set(existing)) {
            n00b_mmap_info_t *m = n00b_option_get(existing);
            if ((uintptr_t)m->start == (uintptr_t)lowest
                && (uintptr_t)m->end == (uintptr_t)highest) {
                reuse = m;
            }
        }
        thread->stack_map = reuse
                                ? reuse
                                : n00b_option_get(n00b_mmap_register(
                                      lowest, highest, n00b_mmap_stack));
    }
}

// ============================================================================
// Thread spawn / join
// ============================================================================

// Bundle handed to the raw worker as its single entry argument.  Lives in
// the runtime's pinned system_pool (never moved by the GC) so the worker
// can safely deref it in the window before it is registered with the
// runtime (see the race note in n00b_thread_spawn).
typedef struct {
    void *(*fn)(void *);
    void             *arg;
    uint32_t          tid;       // pre-reserved slot
    n00b_callstack_t *callstack; // OS stack the worker runs on
    n00b_callstack_t *altstack;  // WP-3b: crash-handler alternate signal stack
                                 // (pool region; returned at death by the reaper,
                                 // like `callstack`).  nullptr if the pool draw
                                 // failed — the worker then runs without one.
    n00b_futex_t      ready;     // launcher signals "initialized"
    void             *tcb;       // minimal platform TSD block (D-021); reclaimed by the reaper
    // OS-death-edge liveness primitive (WP-3a Phase 2, D-034), seeded by the
    // spawner in _n00b_os_thread_create and copied onto the worker's struct by
    // the launcher so the reaper can test the worker's true death.  macOS: the
    // Mach thread port from thread_create.  Linux: the CLONE_CHILD_CLEARTID
    // child-tid futex word lives here (clone()'s ctid points at &bundle->child_tid);
    // the launcher records its address on self->child_tid_word for the reaper.
    uint32_t          os_thread_port; // macOS Mach port (0 on other platforms)
    // Linux CLONE_CHILD_CLEARTID child-tid word (WP-3a Phase 2, D-034).  Lives
    // here (stable system_pool) because clone()'s ctid is fixed at create time,
    // before the worker allocates its permanent struct.  Seeded nonzero by the
    // spawner; the kernel writes 0 at true thread exit.  The launcher records
    // its address on self->child_tid_word for the reaper.  Unused off Linux.
    _Atomic(uint32_t) child_tid;
    void             *os_thread_handle; // Win32 thread handle (nullptr elsewhere)
    _Atomic(n00b_thread_t *) self; // worker publishes its permanent struct here before ready

    // Spawn attributes (WP-002) carried spawner->launcher.  The launcher
    // copies these onto the published `self` struct (on the worker, where
    // n00b_thread_self() resolves), applies `name` via the per-OS raw thread-name
    // primitive, and runs `finalizer` exactly once on the worker's exit path
    // before the join wake.
    n00b_string_t   *name;           // OS thread name (nullptr = unnamed)
    n00b_finalizer_t finalizer;      // run once on worker exit (nullptr = none)
    void            *finalizer_data; // opaque arg passed to finalizer

    // Scheduling attributes (WP-002 Phase 3, D-025).  The launcher applies
    // these on the worker (after init, where n00b_thread_self() resolves) via the per-OS
    // raw primitive, then records the request on the published struct.  The
    // raw escape (when set) bypasses the tier mapping.
    n00b_thread_tier_t      sched_tier;    // resolved tier (DEFAULT = none)
    bool                    sched_raw_set; // true when sched_raw is valid
    n00b_thread_sched_raw_t sched_raw;     // raw per-OS {policy, priority}

    // Affinity attribute (WP-002 Phase 4, D-025).  The launcher applies this on
    // the worker (after init, where n00b_thread_self() resolves) via the per-OS primitive —
    // hard pin on Linux/Win32, advisory on macOS — then records the request on
    // the published struct.  An empty set (mask == 0) means none was requested.
    n00b_thread_cpuset_t    affinity;      // requested CPU-id set (mask 0 = none)

    // Isolation attribute (WP-002 Phase 5, D-025 Q1).  When true, the launcher
    // sets self->gc_isolated on the worker so the GC EXCLUDES the worker's C
    // stack from its conservative range scan (n00b_scan_thread_stacks); the
    // worker self-registers any heap memory it wants kept alive (see the
    // self-registration contract on n00b_thread_spawn).  The thread struct,
    // record, and lock chains are still scanned.
    bool                    isolation;     // true = exclude C stack from conservative scan

    // Crash-handler surface (WP-002 Phase 6, D-025 Q4) carried spawner->launcher.
    // The launcher copies these onto the published `self` struct and does
    // NOTHING ELSE — no signal handler, no sigaltstack, no delivery; crash
    // delivery + the guard-page SIGSEGV handler are WP-3.
    n00b_thread_crash_handler_t crash_handler;      // registered crash callback (nullptr = none)
    void                       *crash_handler_data; // opaque arg for WP-3 delivery
} n00b_tbundle_t;

// ============================================================================
// Minimal n00b-owned per-thread TCB / platform-ABI TSD (D-021).
//
// A raw OS worker starts with a zero thread-pointer register.  Any code
// that reads the thread pointer then faults:
//
//   - macOS arm64: os_unfair_lock / _os_nospin_lock_lock execute
//       mrs x9, TPIDRRO_EL0  ;  ldr w3, [x9, #0x18]  ;  casa ...
//     i.e. they load a 32-bit owner token from slot 3 of the TSD
//     (offset 0x18 == __TSD_MACH_THREAD_SELF * 8); cerror stores errno at
//     slot 1 (offset 0x08 == __TSD_ERRNO).  Verified by disassembly of
//     _os_nospin_lock_lock and the XNU/libpthread TSD slot layout
//     (libsyscall os/tsd.h: __TSD_THREAD_SELF=0, __TSD_ERRNO=1,
//     __TSD_MACH_THREAD_SELF=3).  The slot-3 token is the thread's Mach
//     port (NOT merely a self port — confirmed against a live worker:
//     [TSD+0x18] held the thread_create port, low bit reserved for the
//     lock's "has waiters" flag).
//   - Linux: glibc locks/errno read the thread pointer via %fs.
//
// D-021 resolution: n00b installs its OWN minimal TSD block at worker
// entry so these primitives operate.  On macOS this is done with the
// `_thread_set_tsd_base` machdep trap (x16=0x80000000, x3=2 ->
// thread_set_cthread_self -> machine_thread_set_tsd_base), which lets a
// running Mach thread set its OWN TPIDRRO_EL0 to our block — keeping the
// existing Mach thread_create + thread_set_state path and avoiding both
// the Mach-thread "RO thread pointer" limitation AND libpthread bring-up.
// (bsdthread_create was the originally-named mechanism in D-021 but is
// NOT viable here: the kernel rejects a non-PTHREAD_START_CUSTOM call with
// EINVAL, and a CUSTOM call jumps the child into libpthread's
// process-registered thread_start trampoline — we do not control the PC —
// which runs _pthread_start expecting a real, libpthread-initialized
// pthread_t.  The machdep trap is the off-libpthread primitive that gives
// the SAME result: the kernel sets our thread pointer.  Verified
// empirically: a Mach thread that installs a minimal block this way runs
// os_unfair_lock lock/unlock repeatedly without faulting.)
//
// The block is one zeroed page (so any slot libsystem indexes is mapped
// and zero) mapped via n00b_mmap from a non-GC region; the REAPER frees it
// at OS-confirmed death (WP-3a Phase 2 / D-034 — _n00b_reap_reclaim ->
// _n00b_tcb_free; NOT the joiner, which frees nothing under D-034).  It
// carries no n00b per-thread data (identity stays the stack ID
// word per D-014/D-019; n00b state stays in n00b_thread_t per D-005/D-012)
// — only the platform-ABI slots above.
//
// The worker still keeps its FOUNDATION syscalls TSD-independent: the
// futex WAKE is a direct svc syscall (core/futex.h) and the worker's EXIT
// is a direct bsdthread_terminate (below).  Those run both before and
// after the TSD is torn down on macOS, so they must not depend on it.
// ============================================================================
#ifdef __APPLE__
static inline long
_n00b_darwin_syscall(long n, long a0, long a1, long a2, long a3)
{
    register long x16 __asm__("x16") = n;
    register long x0 __asm__("x0")   = a0;
    register long x1 __asm__("x1")   = a1;
    register long x2 __asm__("x2")   = a2;
    register long x3 __asm__("x3")   = a3;
    __asm__ volatile("svc #0x80"
                     : "+r"(x0)
                     : "r"(x16), "r"(x1), "r"(x2), "r"(x3)
                     : "cc", "memory");
    return x0;
}

// TSD slot indices the platform's lock/errno primitives index (XNU
// libsyscall os/tsd.h).  Each slot is one 64-bit word.
#define N00B_TSD_SLOT_THREAD_SELF      0  // [TSD+0x00] self-pointer
#define N00B_TSD_SLOT_MACH_THREAD_SELF 3  // [TSD+0x18] os_unfair_lock owner token

// libpthread keeps part of `struct _pthread` BELOW the TSD slot array, and
// TPIDRRO_EL0 points AT the slot array (an interior pointer), not the struct
// base.  ___chkstk_darwin (libsystem_pthread) — the compiler-inserted stack
// probe emitted in the prologue of any function with a large stack frame —
// reads the thread's stack bounds from two of those negative-offset fields:
//   [TPIDRRO_EL0 - 0x30] == stack HIGH (stackaddr, one-past-top)
//   [TPIDRRO_EL0 - 0x28] == stack LOW  (limit, lowest usable)
// (Verified by disassembling ___chkstk_darwin on this host: +8 is
//  `ldur x11, [x10, #-0x30]` with x10 = TPIDRRO_EL0.  The `b.hs` at +16 takes
//  the page-probe path only when SP has already grown PAST the top (SP >=
//  [tp-0x30]); a normal downward-growing stack has SP < top, so it falls
//  through to the [tp-0x28] limit check at +20.)  A raw worker crashed in
// exactly this path: arc4random_buf's periodic DRBG *reseed*
// (ccdrbg_df_bc_derive_keys) has a large enough frame to trigger the probe,
// whose first load faults reading [TPIDRRO_EL0 - 0x30] when the thread pointer
// sits at the page base (nothing mapped below it).  The normal arc4random
// *generate* path has small frames, never calls ___chkstk_darwin, and so never
// reads these fields — which is why random worked everywhere else and only the
// (intermittent) reseed faulted.
//
// So the TCB thread pointer is placed at a fixed offset INTO the page (not at
// the base), leaving room below for these fields — mirroring how real
// libpthread uses an interior tsd pointer.  The lock/errno slots (positive
// offsets) move with it; the spawner seeds the two stack-bound fields from the
// worker's callstack region (_n00b_tcb_set_stack_bounds).
#define N00B_TCB_TP_OFFSET             0x100   // thread pointer = page base + this
#define N00B_TCB_CHKSTK_STACK_HIGH_OFF (-0x30) // [tp + off] = stack high (stackaddr)
#define N00B_TCB_CHKSTK_STACK_LOW_OFF  (-0x28) // [tp + off] = stack low  (limit)

// The thread pointer (TPIDRRO_EL0 base) for a TCB page from _n00b_tcb_alloc —
// an INTERIOR pointer, NOT the page base (which is what the reaper munmaps).
static inline void *
_n00b_tcb_tp(void *tcb_page)
{
    return (char *)tcb_page + N00B_TCB_TP_OFFSET;
}

// Machdep syscall index for thread_set_cthread_self (machdep_call_table[2]),
// invoked through the 0x80000000-marked machdep trap.  This is exactly what
// libsyscall's __thread_set_tsd_base issues (custom.s, arm64):
//   x0 = tsd_base ; x3 = 2 ; x16 = 0x80000000 ; svc #0x80
#define N00B_MACHDEP_SET_CTHREAD_SELF 2
#define N00B_MACHDEP_SYSCALL_MARKER   0x80000000L

// Install @p tsd as the calling Mach thread's own thread pointer
// (TPIDRRO_EL0 base).  After this returns, os_unfair_lock and the rest of
// the platform's TSD-reading primitives operate on this block.  TSD-free
// itself (a raw machdep trap; touches no TSD slot), so it is safe to call
// as the very first thing a raw worker does.
static inline void
_n00b_darwin_set_thread_pointer(void *tsd)
{
    register long x0 __asm__("x0")   = (long)(uintptr_t)tsd;
    register long x3 __asm__("x3")   = N00B_MACHDEP_SET_CTHREAD_SELF;
    register long x16 __asm__("x16") = N00B_MACHDEP_SYSCALL_MARKER;
    __asm__ volatile("svc #0x80"
                     : "+r"(x0)
                     : "r"(x3), "r"(x16)
                     : "cc", "memory");
}
#endif // __APPLE__

// ============================================================================
// Minimal TCB allocation (n00b-owned, non-GC).  One zeroed page mapped via
// n00b_mmap so the GC never moves it and every TSD slot the OS might index
// is mapped and zero-initialized.  On macOS we additionally seed the two
// slots the platform's lock/errno paths read (self-pointer + Mach-port
// token).  Returns nullptr on failure (the spawn path surfaces ENOMEM).
// ============================================================================
#ifndef _WIN32
// One page, raw-mmap'd and NOT registered in the mmap interval tree: the
// TCB is never GC-scanned as a root and never looked up by address, so it
// needs no tree entry — and keeping it out of the tree avoids adding
// per-worker churn to the (known-fragile) interval tree on the shutdown
// path.  Unmapped via n00b_safe_munmap, the canonical primitive for an
// unregistered region (matching the callstack's raw-unmap pattern).
static _Atomic uint64_t n00b_tcb_alloc_count;
static _Atomic uint64_t n00b_tcb_free_count;
static _Atomic uint64_t n00b_tcb_alloc_failures;
static _Atomic uint64_t n00b_tcb_current_count;
static _Atomic uint64_t n00b_tcb_current_bytes;
static _Atomic uint64_t n00b_tcb_high_water_count;
static _Atomic uint64_t n00b_tcb_high_water_bytes;

static inline void
_n00b_tcb_update_high_water(_Atomic uint64_t *target, uint64_t value)
{
    for (;;) {
        uint64_t old = n00b_atomic_load(target);
        if (value <= old) {
            return;
        }
        if (n00b_cas(target, &old, value)) {
            return;
        }
    }
}

static inline void
_n00b_tcb_record_alloc(size_t bytes)
{
    uint64_t count = n00b_atomic_add(&n00b_tcb_current_count, 1) + 1;
    uint64_t total = n00b_atomic_add(&n00b_tcb_current_bytes, bytes) + bytes;
    (void)n00b_atomic_add(&n00b_tcb_alloc_count, 1);
    _n00b_tcb_update_high_water(&n00b_tcb_high_water_count, count);
    _n00b_tcb_update_high_water(&n00b_tcb_high_water_bytes, total);
}

static inline void
_n00b_tcb_record_free(size_t bytes)
{
    (void)atomic_fetch_sub_explicit(&n00b_tcb_current_count,
                                    1,
                                    memory_order_acq_rel);
    (void)atomic_fetch_sub_explicit(&n00b_tcb_current_bytes,
                                    bytes,
                                    memory_order_acq_rel);
    (void)n00b_atomic_add(&n00b_tcb_free_count, 1);
}

[[n00b::nogc]] n00b_thread_tcb_stats_t
n00b_thread_tcb_stats(void)
{
    return (n00b_thread_tcb_stats_t){
        .alloc_count      = n00b_atomic_load(&n00b_tcb_alloc_count),
        .free_count       = n00b_atomic_load(&n00b_tcb_free_count),
        .alloc_failures   = n00b_atomic_load(&n00b_tcb_alloc_failures),
        .current_count    = n00b_atomic_load(&n00b_tcb_current_count),
        .current_bytes    = n00b_atomic_load(&n00b_tcb_current_bytes),
        .high_water_count = n00b_atomic_load(&n00b_tcb_high_water_count),
        .high_water_bytes = n00b_atomic_load(&n00b_tcb_high_water_bytes),
        .page_size_bytes  = (uint64_t)n00b_page_size,
    };
}

static inline size_t
_n00b_tcb_map_size(void)
{
#if defined(__linux__) && defined(__aarch64__)
    // glibc/aarch64's dynamic TLS resolver reads TCB fields at negative
    // offsets from TPIDR_EL0 (observed: tp - 0x720).  Raw clone workers are
    // not pthreads, but signal/runtime paths can still enter __tls_get_addr,
    // so provide a mapped page below the TP as minimal headroom.
    return (size_t)n00b_page_size * 2;
#else
    return (size_t)n00b_page_size;
#endif
}

#if defined(__linux__)
static inline void *
_n00b_linux_clone_tls(void *tcb_page)
{
#if defined(__aarch64__)
    return (char *)tcb_page + n00b_page_size;
#else
    return tcb_page;
#endif
}
#endif

static void *
_n00b_tcb_alloc(uint32_t mach_port)
{
    size_t bytes = _n00b_tcb_map_size();
    auto map_r = n00b_check_mmap(nullptr,
                                 bytes,
                                 N00B_MPROT,
                                 N00B_MFLAG,
                                 -1,
                                 0);
    if (n00b_result_is_err(map_r)) {
        (void)n00b_atomic_add(&n00b_tcb_alloc_failures, 1);
        return nullptr;
    }
    void *tcb = n00b_result_get(map_r);
    _n00b_tcb_record_alloc(bytes);

#ifdef __APPLE__
    // Seed the platform-ABI slots os_unfair_lock / errno read, relative to the
    // INTERIOR thread pointer (page base + N00B_TCB_TP_OFFSET), not the page
    // base — see N00B_TCB_TP_OFFSET.  The page is already kernel-zeroed, so
    // every other slot reads as a benign 0.  The self-pointer slot must hold
    // the thread pointer itself ([tp+0] == tp invariant).  The two chkstk
    // stack-bound fields below the thread pointer are seeded by the spawner
    // (_n00b_tcb_set_stack_bounds), which knows the worker's callstack region.
    void     *tp                          = _n00b_tcb_tp(tcb);
    uint64_t *slots                       = (uint64_t *)tp;
    slots[N00B_TSD_SLOT_THREAD_SELF]      = (uint64_t)(uintptr_t)tp;
    slots[N00B_TSD_SLOT_MACH_THREAD_SELF] = (uint64_t)mach_port;
#else
    (void)mach_port;
#endif

    return tcb;
}

static void
_n00b_tcb_free(void *tcb)
{
    if (tcb != nullptr) {
        size_t bytes = _n00b_tcb_map_size();
        _n00b_tcb_record_free(bytes);
        n00b_safe_munmap(tcb, bytes);
    }
}

#ifdef __APPLE__
// Seed the two stack-bound fields ___chkstk_darwin reads (below the thread
// pointer) from the worker's callstack region, so the stack probe on a
// large-frame libsystem call (e.g. arc4random_buf's periodic DRBG reseed)
// validates against real bounds instead of faulting on an unmapped read.
// Called by the spawner, where the callstack bounds are known.  See
// N00B_TCB_TP_OFFSET for the full rationale.
//
// NOTE: on a genuine overflow ___chkstk_darwin (its +60 path) deliberately
// faults by dereferencing [stack_low - 8] to raise the overflow signal.  We
// pass cs->stack_low (the guard-band END), so [stack_low - 8] lands inside the
// PROT_NONE guard band — correct, and safe because the guard band is a full
// page (N00B_CALLSTACK_GUARD_PAGES >= 1), far deeper than 8 bytes.
static inline void
_n00b_tcb_set_stack_bounds(void *tcb_page, void *stack_low, void *stack_high)
{
    char *tp = (char *)_n00b_tcb_tp(tcb_page);
    *(uintptr_t *)(tp + N00B_TCB_CHKSTK_STACK_HIGH_OFF) = (uintptr_t)stack_high;
    *(uintptr_t *)(tp + N00B_TCB_CHKSTK_STACK_LOW_OFF)  = (uintptr_t)stack_low;
}
#endif // __APPLE__
#endif // !_WIN32

#ifdef __APPLE__

// Terminate the calling raw Mach thread.  bsdthread_terminate(stack,
// freesize, port, sema) with a zero stack/sema just unwinds the kernel
// thread; we keep the callstack mapped (the REAPER returns it to the
// callstack pool at OS-confirmed death — WP-3a Phase 2 / D-034; NOT the
// joiner, which frees nothing), so we pass 0 for the kernel-side free.
[[noreturn]] static void
_n00b_worker_self_terminate(void)
{
    _n00b_darwin_syscall(SYS_bsdthread_terminate, 0, 0, 0, 0);
    __builtin_unreachable();
}
#endif // __APPLE__

// Publish the worker's n00b-local slot id into the ID word at the top of
// its own callstack region, BEFORE the first n00b_thread_self() call, so
// the Phase-1/Phase-2 recovery formula resolves identity for this thread
// (D-014/D-019).  The id word lives at region_start + S - 8.
static inline void
_n00b_worker_write_id_word(n00b_callstack_t *cs, uint32_t slot)
{
    uint64_t *id_word = (uint64_t *)((char *)cs->region_start
                                     + cs->region_size
                                     - N00B_CALLSTACK_ID_WORD_SIZE);
    *id_word = (uint64_t)slot;
}

// Apply the OS thread name for the CALLING (worker) thread via the per-OS
// RAW primitive (D-002/D-009: no pthread_setname_np).  `bytes` is the
// NUL-terminated UTF-8 from the caller's n00b_string_t (an internal helper
// consuming already-validated bytes — the §2.2 exception); `n` is its byte
// length.  A no-op when `bytes` is null.
//
//   - Linux: raw prctl(PR_SET_NAME, name) — names the calling thread; the
//     kernel truncates to 16 bytes (TASK_COMM_LEN) including the NUL.
//   - Win32: SetThreadDescription on the current thread (UTF-16); written
//     only (host-verified by the user later).
//   - macOS: store-on-struct only.  The off-libpthread raw primitive is
//     __proc_info(PROC_INFO_CALL_SETCONTROL, getpid(),
//     PROC_SELFSET_THREADNAME, 0, name, len) — a 6-arg SYS_proc_info — but
//     PROC_INFO_CALL_SETCONTROL is kernel-internal and exposed by NO SDK
//     header, so the exact call number cannot be verified here; guessing it
//     on the worker's critical path is out of bounds (surfaced as a
//     deferral).  The name is still stored on self->name by the caller.
static void
_n00b_os_set_thread_name(const char *bytes, size_t n)
{
    if (bytes == nullptr) {
        return;
    }
#if defined(__linux__)
    // prctl(PR_SET_NAME, ptr) — names the calling thread (raw, libc-free
    // beyond the header-only wrapper).  The kernel copies up to
    // TASK_COMM_LEN (16) bytes including the terminating NUL.
    (void)n;
    (void)prctl(PR_SET_NAME, (unsigned long)(uintptr_t)bytes, 0ul, 0ul, 0ul);
#elif defined(_WIN32)
    // Win32: SetThreadDescription wants UTF-16.  Convert the UTF-8 bytes to
    // wide chars, then name the current thread.  Written-only on this host.
    int wlen = MultiByteToWideChar(CP_UTF8, 0, bytes, (int)n, nullptr, 0);
    if (wlen > 0) {
        wchar_t wbuf[256];
        if (wlen < (int)(sizeof(wbuf) / sizeof(wbuf[0]))) {
            MultiByteToWideChar(CP_UTF8, 0, bytes, (int)n, wbuf, wlen);
            wbuf[wlen] = L'\0';
            (void)SetThreadDescription(GetCurrentThread(), wbuf);
        }
    }
#else
    // macOS / other: store-on-struct only (see the function comment / the
    // surfaced macOS thread-name deferral).
    (void)n;
#endif
}

// ============================================================================
// Scheduling tier / raw escape apply (WP-002 Phase 3, D-025).
//
// Applied on the WORKER ITSELF in the launcher (after init, where n00b_thread_self()
// resolves), via the per-OS RAW primitive — never pthread_setschedparam /
// pthread_attr_setschedparam (D-002/D-009):
//
//   - macOS: Mach thread_policy_set(THREAD_PRECEDENCE_POLICY) with a signed
//     `importance`.  Precedence is the queryable Mach surface (thread_policy_get
//     reads it back) and is best-effort by construction, so it never fails the
//     spawn — the realtime tier maps to the highest precedence rather than a
//     privileged RT scheduler, which is the macOS fail-soft form.  The worker's
//     real Mach thread port was seeded into its TCB (TSD slot 3) by the spawner
//     at thread_create; we read it from there rather than calling
//     mach_thread_self() (which would mint a send right needing teardown).
//   - Linux: raw sched_setscheduler(SCHED_*) + setpriority(nice) on the calling
//     thread (tid 0 = self).  EPERM / failures are IGNORED (fail-soft): an
//     ungrantable privileged tier (realtime without CAP_SYS_NICE) leaves the
//     worker at the OS default, the request is still recorded on the struct,
//     and the spawn succeeds.  Written code-complete; Linux run is BATCHED to a
//     later Docker session (not compiled/tested on this macOS host).
//   - Win32: SetThreadPriority on the current thread.  Written-only.
//
// The tier→per-OS mapping is NOT 1:1; the table is documented on
// n00b_thread_tier_t in thread.h.  When the raw escape is set it bypasses the
// tier mapping and the {policy, priority} go straight to the primitive.
// ============================================================================

#if defined(__linux__)
// Linux scheduling policy constants (raw, header-free — these are stable ABI
// values; we do not pull in <sched.h>'s glibc wrappers, only the numbers).
#define N00B_SCHED_OTHER 0
#define N00B_SCHED_FIFO  1
#define N00B_SCHED_RR    2
#define N00B_SCHED_BATCH 3
#define N00B_SCHED_IDLE  5
#define N00B_PRIO_PROCESS 0

// One raw sched_param: a single int rt-priority (the only field the kernel
// reads for sched_setscheduler).  n00b-owned; NOT glibc's struct sched_param.
typedef struct {
    int sched_priority;
} n00b_raw_sched_param_t;

// Apply {policy, nice_or_rtprio} to the CALLING thread via raw syscalls.
// SCHED_FIFO/RR carry an rt-priority; the time-shared policies carry a nice
// value applied via setpriority.  Failures are ignored (fail-soft).
static void
_n00b_linux_apply_sched(int policy, int rt_priority, int nice_value)
{
    n00b_raw_sched_param_t param = {.sched_priority = rt_priority};
    // tid 0 == the calling thread.
    (void)_n00b_raw_linux_syscall3(SYS_sched_setscheduler, 0, policy, (long)(uintptr_t)&param);
    if (policy == N00B_SCHED_OTHER || policy == N00B_SCHED_BATCH
        || policy == N00B_SCHED_IDLE) {
        // nice is set via setpriority on the calling thread (who == 0).
        (void)_n00b_raw_linux_syscall3(SYS_setpriority, N00B_PRIO_PROCESS, 0, nice_value);
    }
}
#endif // __linux__

#if defined(_WIN32)
// Map a tier to a Win32 SetThreadPriority level.  Written-only on this host.
static int
_n00b_win_tier_priority(n00b_thread_tier_t tier)
{
    switch (tier) {
    case N00B_THREAD_TIER_IDLE:
        return THREAD_PRIORITY_IDLE;
    case N00B_THREAD_TIER_LOW:
        return THREAD_PRIORITY_BELOW_NORMAL;
    case N00B_THREAD_TIER_HIGH:
        return THREAD_PRIORITY_ABOVE_NORMAL;
    case N00B_THREAD_TIER_REALTIME:
        return THREAD_PRIORITY_TIME_CRITICAL;
    case N00B_THREAD_TIER_NORMAL:
    default:
        return THREAD_PRIORITY_NORMAL;
    }
}
#endif // _WIN32

// Apply a resolved scheduling request to the calling (worker) thread.  When
// @p raw_set is true, @p raw is applied directly (tier mapping bypassed);
// otherwise @p tier is mapped per-OS.  Always fail-soft.  @p self carries the
// worker's TCB (used on macOS to recover the Mach thread port).
static void
_n00b_apply_sched(n00b_thread_t *self,
                  n00b_thread_tier_t tier,
                  bool raw_set,
                  n00b_thread_sched_raw_t raw)
{
    if (tier == N00B_THREAD_TIER_DEFAULT && !raw_set) {
        return; // nothing requested.
    }

#if defined(__APPLE__)
    // The worker's real Mach thread port was seeded into TSD slot 3 of its TCB
    // by the spawner (thread_create).  Read it back rather than minting a new
    // send right via mach_thread_self().
    mach_port_t mp = MACH_PORT_NULL;
    if (self != nullptr && self->tcb != nullptr) {
        uint64_t *slots = (uint64_t *)_n00b_tcb_tp(self->tcb);
        mp              = (mach_port_t)slots[N00B_TSD_SLOT_MACH_THREAD_SELF];
    }
    if (mp == MACH_PORT_NULL) {
        return; // cannot recover the port; fail-soft.
    }

    // REALTIME tier: THREAD_TIME_CONSTRAINT_POLICY, not precedence.  A raw Mach
    // thread (no pthread → no pthread QoS class) cannot be lifted above OTHER
    // PROCESSES' threads by THREAD_PRECEDENCE_POLICY — precedence ranks threads
    // only WITHIN this task, so it cannot keep the worker scheduled when the
    // whole machine is oversubscribed (e.g. a Docker VM + a compiler swarm at
    // load > 100).  Time-constraint places the worker in the real-time band,
    // which is the cross-process lever available without a pthread.  Conservative
    // and PREEMPTIBLE so it earns low scheduling latency without monopolising a
    // core: a sporadic (period 0) server allowed up to ~3 ms of compute within a
    // ~10 ms deadline.  Unprivileged on macOS (audio apps use it); fail-soft —
    // if the timebase is unavailable we fall through to precedence below.
    if (!raw_set && tier == N00B_THREAD_TIER_REALTIME) {
        mach_timebase_info_data_t tb = {};
        if (mach_timebase_info(&tb) == KERN_SUCCESS && tb.numer != 0
            && tb.denom != 0) {
            uint64_t num  = (uint64_t)tb.numer;
            uint64_t den  = (uint64_t)tb.denom;
            // ns -> mach abstime ticks; clamp to uint32 so a pathological timer
            // ratio (e.g. an emulated host) cannot silently wrap the field.
            uint64_t comp = 3000000ull * den / num;   // 3 ms
            uint64_t cons = 10000000ull * den / num;  // 10 ms
            if (comp > UINT32_MAX) {
                comp = UINT32_MAX;
            }
            if (cons > UINT32_MAX) {
                cons = UINT32_MAX;
            }
            thread_time_constraint_policy_data_t rt = {
                .period      = 0,
                .computation = (uint32_t)comp,
                .constraint  = (uint32_t)cons,
                .preemptible = 1,
            };
            (void)thread_policy_set((thread_act_t)mp,
                                    THREAD_TIME_CONSTRAINT_POLICY,
                                    (thread_policy_t)&rt,
                                    THREAD_TIME_CONSTRAINT_POLICY_COUNT);
            return;
        }
    }

    integer_t importance;
    if (raw_set) {
        // Raw escape: `priority` is the signed Mach importance.  (`policy`
        // currently always selects THREAD_PRECEDENCE_POLICY.)
        importance = (integer_t)raw.priority;
    }
    else {
        switch (tier) {
        case N00B_THREAD_TIER_IDLE:
            importance = -2;
            break;
        case N00B_THREAD_TIER_LOW:
            importance = -1;
            break;
        case N00B_THREAD_TIER_HIGH:
            importance = 1;
            break;
        case N00B_THREAD_TIER_REALTIME:
            importance = 2;
            break;
        case N00B_THREAD_TIER_NORMAL:
        default:
            importance = 0;
            break;
        }
    }

    thread_precedence_policy_data_t policy = {.importance = importance};
    // Best-effort: precedence is never privileged, so this does not fail the
    // spawn even for the realtime tier (fail-soft, D-025).
    (void)thread_policy_set((thread_act_t)mp,
                            THREAD_PRECEDENCE_POLICY,
                            (thread_policy_t)&policy,
                            THREAD_PRECEDENCE_POLICY_COUNT);
#elif defined(__linux__)
    (void)self;
    if (raw_set) {
        // Raw escape: `policy` is the SCHED_* constant; `priority` is the
        // rt-priority (FIFO/RR) or the nice value (OTHER/BATCH/IDLE).
        int policy = (int)raw.policy;
        if (policy == N00B_SCHED_FIFO || policy == N00B_SCHED_RR) {
            _n00b_linux_apply_sched(policy, (int)raw.priority, 0);
        }
        else {
            _n00b_linux_apply_sched(policy, 0, (int)raw.priority);
        }
        return;
    }
    switch (tier) {
    case N00B_THREAD_TIER_IDLE:
        _n00b_linux_apply_sched(N00B_SCHED_IDLE, 0, 19);
        break;
    case N00B_THREAD_TIER_LOW:
        _n00b_linux_apply_sched(N00B_SCHED_OTHER, 0, 10);
        break;
    case N00B_THREAD_TIER_HIGH:
        _n00b_linux_apply_sched(N00B_SCHED_OTHER, 0, -10);
        break;
    case N00B_THREAD_TIER_REALTIME:
        // SCHED_FIFO needs CAP_SYS_NICE; on EPERM this is a no-op (fail-soft).
        _n00b_linux_apply_sched(N00B_SCHED_FIFO, 10, 0);
        break;
    case N00B_THREAD_TIER_NORMAL:
    default:
        _n00b_linux_apply_sched(N00B_SCHED_OTHER, 0, 0);
        break;
    }
#elif defined(_WIN32)
    (void)self;
    int level = raw_set ? (int)raw.priority : _n00b_win_tier_priority(tier);
    // Best-effort on the current thread (fail-soft).
    (void)SetThreadPriority(GetCurrentThread(), level);
#else
    (void)self;
    (void)tier;
    (void)raw_set;
    (void)raw;
#endif
}

// ============================================================================
// Affinity apply (WP-002 Phase 4, D-025).
//
// Applied on the WORKER ITSELF in the launcher (after init, where n00b_thread_self()
// resolves), via the per-OS RAW primitive — never pthread_setaffinity_np
// (D-002/D-009):
//
//   - Linux: HARD PIN via raw sched_setaffinity(0, sizeof(unsigned long),
//     &mask) (tid 0 = self).  The 64-bit set IS the raw kernel cpu-set on
//     LP64 (one unsigned long, low bit = CPU 0); we build the bitmask + size
//     ourselves rather than pulling in glibc's cpu_set_t / CPU_SET macros.
//     Failures (e.g. a mask naming no online CPU) are IGNORED (fail-soft).
//     Written code-complete; the Linux run is BATCHED to a later Docker
//     session (not compiled/tested on this macOS host).
//   - Win32: HARD PIN via SetThreadAffinityMask(GetCurrentThread(), mask).
//     Written-only on this host.
//   - macOS: ADVISORY ONLY.  Darwin exposes no hard CPU pin; we apply Mach
//     thread_policy_set(THREAD_AFFINITY_POLICY) with an affinity_tag derived
//     from the set (1-based lowest set CPU).  This is a scheduler HINT, not a
//     pin, and is best-effort (never fails the spawn).
//
// An empty set (mask == 0) requests no affinity and makes no syscall.
// ============================================================================

// Index of the lowest set bit in a nonzero mask (0-based).  Mask must be != 0.
static inline int
_n00b_cpuset_lowest(uint64_t mask)
{
    return __builtin_ctzll(mask);
}

// Apply a requested CPU-id set to the calling (worker) thread.  Always
// fail-soft.  @p self carries the worker's TCB (used on macOS to recover the
// Mach thread port, as _n00b_apply_sched does).
static void
_n00b_apply_affinity(n00b_thread_t *self, n00b_thread_cpuset_t set)
{
    if (set.mask == 0) {
        return; // no affinity requested.
    }

#if defined(__APPLE__)
    // ADVISORY: Darwin has no hard pin.  Map the set to an L2-affinity tag (the
    // 1-based lowest set CPU, so 0 stays reserved for THREAD_AFFINITY_TAG_NULL)
    // and hint the scheduler via THREAD_AFFINITY_POLICY on the worker's real
    // Mach port (seeded into TSD slot 3 by the spawner, as _n00b_apply_sched).
    mach_port_t mp = MACH_PORT_NULL;
    if (self != nullptr && self->tcb != nullptr) {
        uint64_t *slots = (uint64_t *)_n00b_tcb_tp(self->tcb);
        mp              = (mach_port_t)slots[N00B_TSD_SLOT_MACH_THREAD_SELF];
    }
    if (mp == MACH_PORT_NULL) {
        return; // cannot recover the port; fail-soft.
    }

    thread_affinity_policy_data_t policy = {
        .affinity_tag = (integer_t)(_n00b_cpuset_lowest(set.mask) + 1),
    };
    // Best-effort: this is a hint, never privileged, so it does not fail the
    // spawn (advisory, D-025 Q2b).
    (void)thread_policy_set((thread_act_t)mp,
                            THREAD_AFFINITY_POLICY,
                            (thread_policy_t)&policy,
                            THREAD_AFFINITY_POLICY_COUNT);
#elif defined(__linux__)
    (void)self;
    // HARD PIN: the 64-bit set is the raw kernel cpu-set on LP64 (one unsigned
    // long, low bit = CPU 0).  Hand it to the syscall directly with
    // cpusetsize = sizeof(unsigned long) — no glibc cpu_set_t / CPU_SET.  tid 0
    // == the calling thread.  Failures are ignored (fail-soft).
    unsigned long kmask = (unsigned long)set.mask;
    (void)_n00b_raw_linux_syscall3(SYS_sched_setaffinity, 0, sizeof(unsigned long), (long)(uintptr_t)&kmask);
#elif defined(_WIN32)
    (void)self;
    // HARD PIN on the current thread; the DWORD_PTR mask is the set truncated
    // to pointer width.  Best-effort (fail-soft).
    (void)SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)set.mask);
#else
    (void)self;
    (void)set;
#endif
}

// ============================================================================
// OS-death-edge reclamation: the reaper (WP-3a Phase 2, D-034).
//
// D-034 moves a worker's callstack + TCB reclamation OFF the (buggy) join
// handshake and ONTO the OS-confirmed-death edge.  The WP-1 join freed the
// callstack/TCB the instant it observed join_futex == 1 — but the worker is
// STILL on that stack then (it goes on to run n00b_futex_wake +
// _n00b_worker_self_terminate).  Pooled reuse of a still-live stack would be
// catastrophic, so reclamation now waits until the OS confirms the worker is
// truly off its stack:
//
//   - macOS: the worker self-terminates via bsdthread_terminate
//     (_n00b_worker_self_terminate); its Mach thread port then goes dead.
//     thread_info(port, THREAD_BASIC_INFO, …) returns KERN_SUCCESS while the
//     thread is alive and a non-success error once it is gone (verified: a
//     self-terminated worker's control-port name becomes a dead name and
//     thread_info fails with MACH_SEND_INVALID_DEST).  That transition is the
//     death edge.  Once confirmed, the reaper deallocates the port name so it
//     cannot be recycled out from under us.
//   - Linux: clone() is given CLONE_CHILD_CLEARTID with ctid = &bundle->child_tid;
//     the kernel writes 0 to that word and futex-wakes it at true thread exit.
//     The spawner seeds it nonzero, so a 0 there is the unambiguous death edge.
//     (Written-complete this WP; Docker-verified later, D-026/D-028.)
//   - Windows: CreateThread returns a thread handle that becomes signaled only
//     after the worker has exited.  The reaper waits for that signal before
//     closing the handle and recycling the n00b callstack.
//
// The reaper owns ONLY the callstack (-> pool), the TCB (-> free), and the
// macOS port (-> deallocate).  It does NOT touch rt->threads[slot] or the
// generation: n00b_thread_destroy already cleared the slot under its release
// gate (stack_lo then stack_hi then thread = nullptr) on the worker's own exit
// path, releasing the slot for reuse, and n00b_thread_init bumps the generation
// when a slot is (re)acquired.  Having the reaper re-clear the slot would be a
// race: a new worker may have acquired the freed slot between destroy and reap,
// and re-clearing rec->thread would null out the LIVE new worker.  So the slot
// clear / generation bump stay where they are (destroy + init); this resolves
// DF-5 (generation-bump placement) — init-time bump suffices because identity
// is per-CALLSTACK-region (the SP-mask reads the id word the CURRENT region's
// worker wrote), not per-slot, so a stale n00b_thread_t * cannot alias a reused
// slot's new worker via self().  The struct itself is GC-owned (user_pool,
// D-034); the reaper never frees it.
//
// Reaper placement (D-034): amortized on the callstack-pool slow path (a spawn
// needing a callstack first sweeps the queue) + the conduit signal thread as a
// prompt backstop.  No dedicated reaper thread.
// ============================================================================

// Enqueue a worker on the runtime reap-pending queue (called by the worker at
// its launcher exit, just before self-terminate).  A tiny test-and-set spinlock
// guards the singly-linked queue; the splice is O(1).
static void
_n00b_reap_enqueue(n00b_runtime_t *rt, n00b_thread_t *self)
{
    if (rt == nullptr || self == nullptr) {
        return;
    }
    uint32_t expected;
    do {
        expected = 0;
    } while (!n00b_cas(&rt->reap_lock, &expected, 1));

    self->reap_next  = rt->reap_pending;
    rt->reap_pending = self;

    n00b_atomic_store(&rt->reap_lock, 0);
}

// Test whether a queued worker's OS death edge has fired (it is truly off its
// stack).  Per-OS; see the block comment above.
static bool
_n00b_reap_worker_is_dead(n00b_thread_t *t)
{
#if defined(__APPLE__)
    if (t->os_thread_port == 0) {
        // No control port recorded yet (pre-registration transient); treat as
        // not-yet-confirmed rather than reclaiming blind.
        return false;
    }
    thread_basic_info_data_t info;
    mach_msg_type_number_t   count = THREAD_BASIC_INFO_COUNT;
    kern_return_t            kr    = thread_info((thread_act_t)t->os_thread_port,
                                                 THREAD_BASIC_INFO,
                                                 (thread_info_t)&info,
                                                 &count);
    // KERN_SUCCESS => still alive; any error => the thread (and its port) is
    // gone.  The worker self-terminated via bsdthread_terminate, so once it is
    // off the stack the control-port name is dead and thread_info fails.
    return kr != KERN_SUCCESS;
#elif defined(__linux__)
    // CLONE_CHILD_CLEARTID: the kernel zeroes *t->child_tid_word at true exit.
    // Written-complete; Docker-verified later (D-026/D-028).
    if (t->child_tid_word == nullptr) {
        return false;
    }
    return n00b_atomic_load(t->child_tid_word) == 0;
#elif defined(_WIN32)
    if (t->os_thread_handle == nullptr) {
        return false;
    }
    return WaitForSingleObject((HANDLE)t->os_thread_handle, 0) == WAIT_OBJECT_0;
#else
    return true;
#endif
}

// DIAGNOSTIC (2026-06-02, foreign-self aliasing evidence): called at the start
// of a collect (under STW).  Tests the hypothesis that a LIVE foreign collector
// thread resolved n00b_thread_self() to a DEAD-but-unreaped foreign record whose
// stack bounds alias this thread's reused libdispatch stack.  Two independent
// smoking guns, either of which proves it:
//   (1) self_port_dead: the record we resolved to has a Mach port that
//       thread_info reports DEAD — impossible for the record of the thread we
//       are actually running on, so we aliased another (dead) thread's record.
//   (2) overlap: some OTHER live slot's [stack_lo,stack_hi) ALSO contains our
//       real SP, and that mate's port is dead — a dead record still advertising
//       our reused stack range.
// Self-limiting (logs the first 32).  Remove once the identity fix lands.
void
n00b_diag_foreign_self_check(void)
{
#if defined(__APPLE__)
    static _Atomic int n_logged = 0;
    if (n00b_atomic_load(&n_logged) >= 32) {
        return;
    }

    n00b_runtime_t *rt = n00b_get_runtime();
    if (rt == nullptr || rt->threads == nullptr || rt->live_slot_bits == nullptr) {
        return;
    }

    n00b_thread_t *self = n00b_thread_self();
    if (self == nullptr) {
        return;
    }
    n00b_thread_record_t *srec = self->record;

    // First: classify the collecting thread (first 16 collects) so we KNOW
    // whether collects ever run on a foreign thread at all — if they never do,
    // the foreign-self-aliasing hypothesis cannot explain the gc.c:211 crash.
    {
        static _Atomic int n_class = 0;
        if (n00b_atomic_load(&n_class) < 16) {
            n00b_atomic_add(&n_class, 1);
            const char *kind = (self->id_info.parts.id == N00B_MAIN_THREAD_SLOT)
                                   ? "MAIN"
                               : (self->callstack != nullptr) ? "WORKER"
                               : (self->os_thread_port != 0)  ? "FOREIGN"
                                                              : "OTHER";
            fprintf(stderr,
                    "DIAG-SELF: kind=%s slot=%u callstack=%p port=%u\n",
                    kind,
                    (uint32_t)self->id_info.parts.id,
                    (void *)self->callstack,
                    self->os_thread_port);
        }
    }

    // Foreign = no callstack + not the main thread.  (main now carries a real
    // Mach port too — WP-001/WP-4 — so it is identified by slot, not port==0.)
    if (self->callstack != nullptr || n00b_thread_is_main(self) || srec == nullptr) {
        return;
    }

    volatile int sp_anchor = 0;
    uintptr_t    p         = (uintptr_t)&sp_anchor;
    uint32_t     self_slot = (uint32_t)self->id_info.parts.id;

    bool self_port_dead = _n00b_reap_worker_is_dead(self);

    // Any OTHER live slot whose advertised bounds also contain our real SP?
    int      overlap = 0;
    uint32_t omate   = 0;
    void    *olo = nullptr, *ohi = nullptr;
    uint32_t oport = 0;
    int      odead = 0;
    for (uint32_t i = 0; i < rt->max_threads; i++) {
        if (i == self_slot) {
            continue;
        }
        uint64_t bit = (uint64_t)1 << (i & 63u);
        if (!(n00b_atomic_load(&rt->live_slot_bits[i >> 6]) & bit)) {
            continue;
        }
        void *lo = n00b_atomic_load(&rt->threads[i].stack_lo);
        void *hi = n00b_atomic_load(&rt->threads[i].stack_hi);
        if (lo == nullptr || hi == nullptr) {
            continue;
        }
        if (p >= (uintptr_t)lo && p < (uintptr_t)hi) {
            if (overlap++ == 0) {
                omate            = i;
                olo              = lo;
                ohi              = hi;
                n00b_thread_t *ot = n00b_atomic_load(&rt->threads[i].thread);
                if (!n00b_thread_slot_is_vacant(ot)) {
                    oport = ot->os_thread_port;
                    odead = _n00b_reap_worker_is_dead(ot);
                }
            }
        }
    }

    if (self_port_dead || overlap > 0) {
        n00b_atomic_add(&n_logged, 1);
        fprintf(stderr,
                "FOREIGN-SELF-DIAG: sp=%p resolved=slot%u self[lo=%p hi=%p] "
                "self_port=%u self_port_DEAD=%d | overlap_live_slots=%d "
                "first=slot%u[lo=%p hi=%p] port=%u dead=%d\n",
                (void *)p,
                self_slot,
                n00b_atomic_load(&srec->stack_lo),
                n00b_atomic_load(&srec->stack_hi),
                self->os_thread_port,
                (int)self_port_dead,
                overlap,
                omate,
                olo,
                ohi,
                oport,
                odead);
    }
#endif
}

// Reclaim a single confirmed-dead worker's OS resources (D-034).  Returns the
// callstack region to the pool, frees the TCB, and (macOS) deallocates the now
// dead port name.  Does NOT touch the slot/generation/struct (see the block
// comment).
static void
_n00b_reap_reclaim(n00b_thread_t *t)
{
#ifndef _WIN32
    if (t->tcb != nullptr) {
        _n00b_tcb_free(t->tcb);
        t->tcb = nullptr;
    }
#endif
#if defined(__APPLE__)
    if (t->os_thread_port != 0) {
        // Drop our reference to the (now dead) thread-port name so it cannot
        // be recycled by a later thread_create under us.
        (void)mach_port_deallocate(mach_task_self(),
                                   (mach_port_name_t)t->os_thread_port);
        t->os_thread_port = 0;
    }
#elif defined(_WIN32)
    if (t->os_thread_handle != nullptr) {
        CloseHandle((HANDLE)t->os_thread_handle);
        t->os_thread_handle = nullptr;
    }
#endif
    if (t->callstack != nullptr) {
        n00b_callstack_t *cs = t->callstack;
        t->callstack         = nullptr;
        n00b_callstack_pool_return(cs);
    }

    // WP-3b (D-039): return the worker's crash-handler altstack to the pool and
    // clear it.  It lives on THIS worker's own struct (not the shared slot
    // record), so even if the slot was already reused by a newer worker, we
    // return only THIS dead worker's region — never a live worker's.  The thread
    // is OS-dead here, so its sigaltstack registration is already gone, making
    // the return safe.
    {
        n00b_callstack_t *as = n00b_atomic_load(&t->altstack);
        if (as != nullptr) {
            n00b_atomic_store(&t->altstack, (n00b_callstack_t *)nullptr);
            n00b_callstack_pool_return(as);
        }
    }

    n00b_atomic_store(&t->reap_futex, 1);
    n00b_futex_wake(&t->reap_futex, true);
}

// Sweep the reap-pending queue, reclaiming every worker whose OS death edge has
// fired and leaving the rest queued.  Bounded (it walks the queue once) so the
// signal-thread backstop's poll loop is never starved.  Safe to call from any
// thread (the spawn slow path + the conduit signal thread, D-034).
static void
_n00b_reap_sweep(n00b_runtime_t *rt)
{
    if (rt == nullptr) {
        return;
    }

    uint32_t expected;
    do {
        expected = 0;
    } while (!n00b_cas(&rt->reap_lock, &expected, 1));

    // Detach the whole queue under the lock, then process it unlocked so the
    // O(1) splice stays the only work under the spinlock.  Workers that are not
    // yet confirmed dead are re-queued at the end.
    n00b_thread_t *list   = rt->reap_pending;
    rt->reap_pending      = nullptr;
    n00b_atomic_store(&rt->reap_lock, 0);

    n00b_thread_t *still_pending      = nullptr;
    n00b_thread_t *still_pending_tail = nullptr;

    while (list != nullptr) {
        n00b_thread_t *t = list;
        list             = t->reap_next;
        t->reap_next     = nullptr;

        if (_n00b_reap_worker_is_dead(t)) {
            _n00b_reap_reclaim(t);
        }
        else {
            // Keep it queued (still on its stack); preserve order is irrelevant.
            t->reap_next = still_pending;
            still_pending = t;
            if (still_pending_tail == nullptr) {
                still_pending_tail = t;
            }
        }
    }

    if (still_pending == nullptr) {
        return;
    }

    // Splice the not-yet-dead workers back onto the (possibly newly grown)
    // queue under the lock.
    do {
        expected = 0;
    } while (!n00b_cas(&rt->reap_lock, &expected, 1));

    still_pending_tail->reap_next = rt->reap_pending;
    rt->reap_pending              = still_pending;

    n00b_atomic_store(&rt->reap_lock, 0);
}

// Public-to-the-module backstop entry: the conduit signal thread calls this
// each poll iteration so unheld detached workers are reaped promptly (D-034).
// Declared in core/thread.h's internal section; defined here.
//
// Slot-scanning unmanaged-thread reaper.  Foreign (libdispatch/XPC) threads
// attach via n00b_thread_init but may never call n00b_thread_destroy
// (libdispatch recycles them silently), so their slot + n00b_thread_t would
// leak forever and eventually exhaust the slot table.  A dispatch_main() daemon
// can also retire the initial thread while the process continues on dispatch
// workers, leaving the main slot with a dead Mach port.  Unlike n00b raw
// workers, these records never enqueue on reap_pending and never cleared their
// own slot, so this sweep both detects OS death and clears the slot.
//
// MUST be called by the collector with the world stopped (from
// n00b_collect_internal, AFTER the mark+sweep): the per-record teardown mutates
// shared CV-waiter lists, lock chains, the slot table, the stack-bounds bitmap
// and the mmap interval tree, none safe to touch concurrently.
void
n00b_reap_dead_foreign_threads(void)
{
#if defined(__APPLE__)
    n00b_runtime_t *rt = n00b_get_runtime();
    if (rt == nullptr || rt->threads == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < rt->max_threads; i++) {
        n00b_thread_record_t *rec = &rt->threads[i];
        n00b_thread_t        *t   = rec->thread;
        // Unmanaged records carry a recorded Mach port and NO callstack.  Raw
        // workers have a callstack and are reaped via reap_pending.
        if (t == nullptr || t->callstack != nullptr || t->os_thread_port == 0) {
            continue;
        }
        if (!_n00b_reap_worker_is_dead(t)) {
            continue; // still alive — leave it attached
        }

        // SAFETY GUARD (syscall-free, defense-in-depth): never reap a record
        // the RUNNING collector is using as its identity, or whose stack the
        // collector is executing on.  With reclaim-on-attach
        // (n00b_thread_attach_foreign) live foreign threads no longer WEAR a
        // dead record, so this must not trigger in practice — it is the
        // backstop against the gc.c:213 self()-null crash, costing two atomic
        // loads and a self() (no syscalls) per dead record.
        {
            volatile int slot_anchor = 0;
            uintptr_t    sp = (uintptr_t)&slot_anchor;
            void        *lo = n00b_atomic_load(&rec->stack_lo);
            void        *hi = n00b_atomic_load(&rec->stack_hi);
            if (t == n00b_thread_self()
                || (lo && hi && sp >= (uintptr_t)lo && sp < (uintptr_t)hi)) {
                continue; // in use by the collector — leave it attached
            }
        }

        // --- Full teardown, mirroring n00b_thread_destroy (safe under STW). ---

        // 1. Remove the dead thread from any CV waiters list.
        n00b_condition_t *cv = rec->cv_info.current_cv;
        if (cv) {
            (void)n00b_list_remove_all(cv->waiters, t);
            rec->cv_info.current_cv = nullptr;
        }

        // 2. Release any locks and epoch retirements the dead thread still held.
        n00b_release_locks_on_thread_exit(rec);
        n00b_epoch_thread_exit(t);
        // (No cooperative SUSPEND self-mark — the self_lock GC-safe bit is gone
        // with the pure-preemptive STW redesign; this reaper already runs with
        // the world stopped.)

        // 3. Retire the stack-bounds advertisement (live bit first, then bounds).
        n00b_atomic_and(&rt->live_slot_bits[i >> 6],
                        ~((uint64_t)1 << (i & 63u)));
        n00b_atomic_store(&rec->stack_lo, (void *)nullptr);
        n00b_atomic_store(&rec->stack_hi, (void *)nullptr);

        // 4. Do NOT unregister the stack node.  Foreign stack ranges are reused
        //    across successive libdispatch threads and a live successor may
        //    already share this node (capture_stack_base reuses it), so
        //    unregistering here could pull a region a live thread still needs,
        //    or ambiguously delete one of several same-range nodes.  Stack nodes
        //    are bounded by the peak distinct stack ranges (small), so leaving
        //    them registered is the safe, correct choice; the reused node is
        //    re-adopted by the next thread on this stack.

        // 5. Release the slot, drop the Mach port name + live count.
        uint32_t reap_port = t->os_thread_port;
        n00b_atomic_store(&rec->thread, (n00b_thread_t *)nullptr);
        (void)mach_port_deallocate(mach_task_self(),
                                   (mach_port_name_t)reap_port);
        t->os_thread_port = 0;
        n00b_atomic_add(&rt->live_threads, -1);
        n00b_futex_wake((n00b_futex_t *)&rt->live_threads, true);
    }
#endif
}

bool
n00b_thread_quarantine_dead_foreign_for_stw(n00b_thread_record_t *rec,
                                            n00b_thread_t        *t)
{
#if defined(__APPLE__)
    n00b_runtime_t *rt = n00b_get_runtime();
    if (rt == nullptr || rec == nullptr || rt->threads == nullptr
        || rt->live_slot_bits == nullptr) {
        return false;
    }
    if (t == nullptr) {
        t = n00b_atomic_load(&rec->thread);
    }
    if (n00b_thread_slot_is_vacant(t) || t->callstack != nullptr
        || t->os_thread_port == 0) {
        return false;
    }
    if (!_n00b_reap_worker_is_dead(t)) {
        return false;
    }

    /* Never quarantine the running collector's own identity.  A collector that
     * resolves to a dead unmanaged record is a separate attach/self bug and
     * must not be hidden by clearing the record out from under itself. */
    volatile int slot_anchor = 0;
    uintptr_t    sp          = (uintptr_t)&slot_anchor;
    void        *lo          = n00b_atomic_load(&rec->stack_lo);
    void        *hi          = n00b_atomic_load(&rec->stack_hi);
    if (t == n00b_thread_self()
        || (lo != nullptr && hi != nullptr && sp >= (uintptr_t)lo
            && sp < (uintptr_t)hi)) {
        return false;
    }

    ptrdiff_t slot = rec - rt->threads;
    if (slot < 0 || (uint32_t)slot >= rt->max_threads) {
        return false;
    }

    /* Minimal pre-STW quarantine only.  The full reaper runs once stw_active is
     * set, where n00b locks/data locks are no-ops.  Here we just make the dead
     * slot impossible to match, suspend, or scan. */
    n00b_atomic_and(&rt->live_slot_bits[(uint32_t)slot >> 6],
                    ~((uint64_t)1 << ((uint32_t)slot & 63u)));
    n00b_atomic_store(&rec->stack_lo, (void *)nullptr);
    n00b_atomic_store(&rec->stack_hi, (void *)nullptr);
    t->gc_stack_top = nullptr;
    t->stack_top    = nullptr;
    t->stack_map    = nullptr;
    for (int i = 0; i < 31; i++) {
        t->gc_captured_regs[i] = 0;
    }
    n00b_atomic_store(&t->gc_preempt_suspended, false);
    return true;
#else
    (void)rec;
    (void)t;
    return false;
#endif
}

void
n00b_thread_reap_pending(void)
{
    n00b_runtime_t *rt = n00b_get_runtime();
    _n00b_reap_sweep(rt);
    // Dead unmanaged records are reclaimed by the collector under STW
    // (n00b_reap_dead_foreign_threads, called from n00b_collect_internal): the
    // teardown mutates CV/lock chains + the mmap tree, which is only safe with
    // the world stopped — not from this concurrent signal-thread sweep.
}

// Common worker prologue/epilogue, shared by every platform's raw entry
// trampoline.  The trampoline (per OS) sets up the C environment and
// jumps here with the bundle in hand.  This function must keep the
// worker resolvable via n00b_thread_self() at every allocating call (it writes the
// id word first) and must never return on macOS (the caller terminates
// the Mach thread itself).

// Optional hook (libn00b debug substrate): a newly-launched worker self-applies
// any active all-thread hardware watch/breakpoints before running user code.
// Weak so core does not hard-depend on the debug module; a no-op (and cheap)
// when nothing is armed.
[[gnu::weak]] extern void n00b_debug_thread_enroll(void);

static void
n00b_thread_launcher(void *raw)
{
    n00b_tbundle_t *bundle = raw;
    n00b_runtime_t *rt     = n00b_get_runtime();

#ifdef __APPLE__
    // TCB FIRST (D-021): install our minimal TSD block as this Mach thread's
    // thread pointer BEFORE any code that reads it.  n00b_thread_init's first
    // allocation is wrapped in a GC-stack push and runs allocator/lock paths
    // that hit os_unfair_lock (which loads [TPIDRRO_EL0 + 0x18]); on a raw
    // Mach thread the register is zero, so this must precede it.  The block
    // and the Mach-port token were prepared by the spawner.
    _n00b_darwin_set_thread_pointer(_n00b_tcb_tp(bundle->tcb));
#endif

    // Identity FIRST: write our slot id into the callstack ID word so the
    // very next n00b_thread_self() (emitted by the codegen's GC-stack push around the
    // first allocation in n00b_thread_init) resolves to this thread.
    _n00b_worker_write_id_word(bundle->callstack, bundle->tid);

    n00b_thread_init(.runtime        = rt,
                     .acquired_slot  = bundle->tid,
                     .callstack      = bundle->callstack,
                     .os_thread_port = bundle->os_thread_port);

    n00b_thread_t *self = n00b_thread_self();
    n00b_capture_stack_top(self);

    n00b_crash_install_altstack(bundle->altstack); // WP-3b (D-039)

    // Record the TCB on the permanent thread struct so the REAPER can unmap
    // it after this worker exits (the worker must not free its own TSD while
    // still running on it).  Reclamation moved off the joiner onto the
    // OS-death edge (WP-3a Phase 2, D-034).
    self->tcb = bundle->tcb;
    self->os_thread_handle = bundle->os_thread_handle;

    // Record the OS-death-edge liveness primitive on the published struct so
    // the reaper can test this worker's true death (WP-3a Phase 2, D-034).
    // macOS: the Mach thread port (self-terminated worker -> thread_info fails).
    // Linux: seed the CLONE_CHILD_CLEARTID child-tid word nonzero so a later 0
    // (written by the kernel at true exit) is the unambiguous death signal; the
    // clone() ctid argument already points at self->child_tid (set by the
    // spawner before create).
    // The worker's STW control handle (os_thread_port on macOS, os_tid on
    // Linux/Windows) is now set INSIDE n00b_thread_init, BEFORE the worker is
    // published as a STW participant (WP-001 Phase 2 ordering), so it is not set
    // again here.  Only the Linux CLONE_CHILD_CLEARTID death-edge word — which
    // is the reaper's liveness primitive, distinct from the STW handle — remains
    // launcher-specific (it points into the stable per-spawn bundle, known only
    // here).
#if defined(__linux__)
    // Record the address of the CLONE_CHILD_CLEARTID word (in the stable
    // bundle) so the reaper can observe the kernel's exit-time 0 store via
    // self.  Written-complete; Docker-verified later (D-026/D-028).
    self->child_tid_word = &bundle->child_tid;
#endif

    // Copy the spawn attributes (WP-002) onto the published struct, on the
    // worker where n00b_thread_self() resolves.  `name` is applied to the OS via the
    // per-OS raw primitive AND stored on self; `finalizer`/`finalizer_data`
    // are stored for the exit path below (run once, before the join wake).
    self->name           = bundle->name;
    self->finalizer      = bundle->finalizer;
    self->finalizer_data = bundle->finalizer_data;

    // Scheduling request (WP-002 Phase 3, D-025): record the REQUEST on the
    // struct (survives even when the OS cannot grant it — fail-soft), then
    // apply it to this worker's OS thread via the per-OS raw primitive.
    self->sched_tier    = bundle->sched_tier;
    self->sched_raw_set = bundle->sched_raw_set;
    self->sched_raw     = bundle->sched_raw;
    _n00b_apply_sched(self,
                      self->sched_tier,
                      self->sched_raw_set,
                      self->sched_raw);

    // Affinity request (WP-002 Phase 4, D-025): record the REQUEST on the
    // struct (survives even when the OS could not honor it — fail-soft), then
    // apply it to this worker's OS thread via the per-OS primitive (hard pin on
    // Linux/Win32, advisory on macOS).
    self->affinity = bundle->affinity;
    _n00b_apply_affinity(self, self->affinity);

    // Isolation request (WP-002 Phase 5, D-025 Q1): record it on the published
    // struct so the GC's scan-set inclusion test (n00b_scan_thread_stacks)
    // EXCLUDES this worker's C stack from the conservative range scan.  This is
    // a plain per-thread flag, not an OS primitive — there is nothing to apply
    // to the OS thread; the GC reads `self->gc_isolated` at collection time.
    // The worker's struct, record, and lock chains are still scanned; the
    // worker self-registers any heap memory it wants kept alive (see the
    // self-registration contract on n00b_thread_spawn).
    self->gc_isolated = bundle->isolation;

    // Crash-handler SURFACE (WP-002 Phase 6, D-025 Q4): STORE the registered
    // handler (+ data) on the published struct so WP-3's delivery path can find
    // it via the crashing worker's struct.  WP-002 does NOTHING ELSE — there is
    // intentionally no signal handler, no sigaltstack, and no delivery path
    // here; crash delivery + the guard-page SIGSEGV handler are WP-3.
    self->crash_handler      = bundle->crash_handler;
    self->crash_handler_data = bundle->crash_handler_data;

    if (self->name != nullptr) {
        // self->name->data is NUL-terminated UTF-8 (core/string.h); hand the
        // bytes to the per-OS raw thread-name set (internal byte-consumer,
        // §2.2 exception).
        _n00b_os_set_thread_name(self->name->data, self->name->u8_bytes);
    }

    // Cache fn/arg locally before signalling the spawner: once ready is
    // set the spawner may free nothing (the bundle is reaped here), but
    // the bundle could be reused conceptually, so read it out first.
    void *(*fn)(void *) = bundle->fn;
    void   *arg         = bundle->arg;

    // Publish our permanent struct into the (stable, system_pool) bundle
    // BEFORE signalling ready.  The spawner returns THIS pointer rather than
    // re-reading rt->threads[slot].thread: a short-lived worker can run fn()
    // and n00b_thread_destroy() (which clears rec->thread to nullptr) before
    // the spawner reads the slot, so the slot is not a stable source for the
    // child handle.  The permanent struct lives in the GC-visible, non-moving
    // user_pool (WP-3a / D-034): it is GC-OWNED — reclaimed once unreferenced,
    // never bulk-freed-at-teardown and never freed by the joiner — and being a
    // pool it never moves, so it outlives the slot clear and the handle stays
    // valid for the subsequent n00b_thread_join (and for as long as the caller
    // holds it).
    n00b_atomic_store(&bundle->self, self);

    // Signal the spawner that init is complete and n00b_thread_self() now resolves.
    // n00b_futex_wake is a direct (TSD-safe) syscall on macOS (futex.h).
    n00b_atomic_store(&bundle->ready, 1);
    n00b_futex_wake(&bundle->ready, true);

    if (n00b_debug_thread_enroll) {
        n00b_debug_thread_enroll();
    }

    void *result = fn(arg);

    // Publish the result, then tear down per-thread state.  We must read
    // join_futex's address off `self` BEFORE n00b_thread_destroy clears
    // the slot, and we must NOT free the callstack here — it is still our
    // running stack.  The REAPER reclaims it at OS-confirmed death (D-034);
    // we enqueue ourselves on rt->reap_pending just below.
    n00b_futex_t *join_futex = &self->join_futex;
    n00b_atomic_store(&self->join_result, result);

    // Publish the 64-bit exit code alongside join_result and BEFORE the
    // join_futex publish-then-wake below (WP-3a, D-032 Q2 / DF-1), so a joiner
    // that observes join_futex == 1 reads a SETTLED code.  This is a SEPARATE
    // channel from `result` (the worker's `void *` fn-return): the worker
    // stashed the code via n00b_thread_exit() during fn() (D-033, stash-only),
    // or left it at its zero default if it never called n00b_thread_exit.
    // No re-store of the code is needed here: the worker stashed it via
    // n00b_thread_exit() during fn() (or it holds its zero default), and that
    // store — like this launcher, which runs on the SAME worker thread — is
    // already sequenced before the join_futex store-release below.  The
    // joiner's join_futex load-acquire therefore observes the settled exit code
    // (and join_result) once it sees join_futex == 1; nothing else writes
    // self->exit_code, so it cannot change between the stash and the wake.

    // Run the spawn finalizer (WP-002) EXACTLY ONCE here, on the worker,
    // BEFORE the join_futex publish-then-wake below: a joiner that observes
    // join_futex == 1 may immediately read the result, so any worker-side
    // cleanup must complete first.  (Reclamation of the callstack/TCB is the
    // reaper's at OS-death, not the joiner's — D-034 — but the finalizer still
    // runs here so it is sequenced before the joiner can act on the result.)
    // It is invoked inline on the single exit path, so it cannot run more than
    // once.  Read the pointers off `self` before n00b_thread_destroy, which
    // does not clear them but keeps the read adjacent to the result publish for
    // clarity.
    n00b_finalizer_t fin      = self->finalizer;
    void            *fin_data = self->finalizer_data;
    if (fin != nullptr) {
        fin(fin_data);
    }

    // Enqueue ourselves on the runtime reap-pending queue BEFORE
    // n00b_thread_destroy clears rec->thread and removes the normal runtime
    // root for this n00b_thread_t. The reaper gates actual reclamation on the
    // OS death edge, so an early sweep will only keep us queued while this
    // worker is still running. Waiting until after destroy leaves a window
    // where the GC can no longer reach the thread struct, but the reaper will
    // later dereference it to return the callstack/altstack.
    _n00b_reap_enqueue(rt, self);

    n00b_thread_destroy();

    // Publish-then-wake: store the "done" flag, then wake any joiner.  After
    // this store the joiner may return the result, but it frees NOTHING of
    // ours (D-034 — the reaper owns reclamation at OS-death); we are still on
    // this callstack, so it must not be recycled until we are truly gone.
    // n00b_futex_wake is a direct (TSD-safe) syscall on macOS (futex.h).
    n00b_atomic_store(join_futex, 1);
    n00b_futex_wake(join_futex, true);

#ifdef __APPLE__
    // The raw Mach worker has no pthread to unwind into and a null lr;
    // terminate the kernel thread directly (errno-free).  This is the macOS
    // death edge: after this, our Mach thread port goes dead and the reaper's
    // thread_info() check fails, gating callstack-pool return / slot clear.
    _n00b_worker_self_terminate();
#endif
}

// ============================================================================
// Per-OS raw worker creation.  Returns 0 on success, or a positive errno
// on failure (the spawn path surfaces it through n00b_result_err).  The
// child enters n00b_thread_launcher(bundle) on the supplied callstack.
// ============================================================================

#if defined(__APPLE__)
// macOS: Mach thread_create + thread_set_state + thread_resume (D-002).
// We set sp to the top of the usable callstack (16-aligned per the AArch64
// ABI), pc to the launcher, x0 to the bundle, and lr to 0 so an accidental
// return faults rather than wanders — the launcher never returns (it
// self-terminates).
static int
_n00b_os_thread_create(n00b_callstack_t *cs, n00b_tbundle_t *bundle)
{
    thread_t      th;
    kern_return_t kr = thread_create(mach_task_self(), &th);
    if (kr != KERN_SUCCESS) {
        return EAGAIN;
    }

    // The thread port is the os_unfair_lock owner token (TSD slot 3,
    // D-021).  Allocate + seed the worker's minimal TSD block now that the
    // port is known; the worker installs it at entry and the REAPER frees it
    // at OS-confirmed death (WP-3a Phase 2 / D-034 — NOT the joiner, which
    // frees nothing).  (Token is the thread's real Mach port: unique, nonzero,
    // low bit free for the lock's waiters flag.)
    bundle->tcb = _n00b_tcb_alloc((uint32_t)th);
    if (bundle->tcb == nullptr) {
        thread_terminate(th);
        return ENOMEM;
    }

    // Seed the chkstk stack-bound fields from this worker's callstack region
    // (D-021 extension): a large-frame libsystem call on the worker (e.g.
    // arc4random_buf's periodic DRBG reseed) runs ___chkstk_darwin, which reads
    // the stack bounds from below the thread pointer.  See N00B_TCB_TP_OFFSET.
    _n00b_tcb_set_stack_bounds(bundle->tcb, cs->stack_low, cs->stack_high);

    // Persist the Mach thread port for the reaper's OS-death check (WP-3a
    // Phase 2, D-034).  After the worker self-terminates via
    // bsdthread_terminate, thread_info() on this port fails — that is the
    // death edge that gates callstack-pool return.  (Previously the port was
    // only seeded into the TCB slot; the reaper needs it on the bundle ->
    // struct.)
    bundle->os_thread_port = (uint32_t)th;

    // Start SP below the identity ID word (which lives at the top word of
    // the region, region_start + S - 8) so the first stack frame can never
    // clobber it; then 16-align down per the AArch64 ABI.
    uintptr_t sp = ((uintptr_t)cs->stack_high - N00B_CALLSTACK_ID_WORD_SIZE)
                 & ~(uintptr_t)15;

    arm_thread_state64_t state = {};
    state.__x[0] = (uint64_t)(uintptr_t)bundle;
    state.__sp   = (uint64_t)sp;
    state.__pc   = (uint64_t)(uintptr_t)&n00b_thread_launcher;
    state.__lr   = 0;

    kr = thread_set_state(th,
                          ARM_THREAD_STATE64,
                          (thread_state_t)&state,
                          ARM_THREAD_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        _n00b_tcb_free(bundle->tcb);
        bundle->tcb = nullptr;
        thread_terminate(th);
        return EINVAL;
    }

    kr = thread_resume(th);
    if (kr != KERN_SUCCESS) {
        _n00b_tcb_free(bundle->tcb);
        bundle->tcb = nullptr;
        thread_terminate(th);
        return EAGAIN;
    }

    return 0;
}

#elif defined(__linux__)
// Linux: raw clone() sharing the address space (CLONE_VM), fd table, fs
// info, signal handlers, thread group, and SysV sem undo — i.e. a real
// sibling thread — WITH CLONE_SETTLS pointing at an n00b-owned minimal
// tcbhead_t (D-021, amending D-012's "no CLONE_SETTLS").  A raw clone()
// without a TLS register leaves %fs at zero, so glibc's lock / errno /
// malloc paths (which read [%fs:offset]) fault on the first real
// workload — the same class of failure D-021 fixes on macOS.  We install
// just enough of the glibc x86-64 `tcbhead_t` ABI that those reads hit
// valid memory: the TCB self-pointer (offset 0, the well-known
// "tcb->tcb == tcb" invariant glibc and the %fs:0x0 self-load rely on)
// and the stack-guard / pointer-guard slots (offsets 0x28 / 0x30) that
// __stack_chk_guard and PTR_MANGLE consult.  Per D-021 this is a minimal
// platform-ABI block, NOT a glibc `struct pthread`: it carries no n00b
// per-thread data (identity stays the stack ID word, D-014/D-019).
//
// NOTE: written-only on this host (macOS).  Not compiled/tested here.
#include <linux/sched.h>

// Minimal glibc-compatible x86-64 TCB head.  Field offsets match glibc's
// `tcbhead_t` for the slots the lock/errno/guard fast paths read; the rest
// of the page is left zero.  %fs.base points HERE (so [%fs:0] == self).
typedef struct {
    void    *tcb;          // 0x00: self-pointer ([%fs:0] -> this block)
    void    *dtv;          // 0x08: dynamic thread vector (unused; zero)
    void    *self;         // 0x10: thread self (unused by our paths; zero)
    int      multiple_threads; // 0x18
    int      gscope_flag;      // 0x1c
    uintptr_t sysinfo;     // 0x20
    uintptr_t stack_guard; // 0x28: __stack_chk_guard source
    uintptr_t pointer_guard;// 0x30: PTR_MANGLE source
} n00b_linux_tcbhead_t;

static int
_n00b_linux_clone_entry(void *raw)
{
    n00b_thread_launcher(raw);
    // The launcher returns on Linux (it does the futex wake itself); exit
    // the cloned thread without touching libc thread teardown.
    (void)_n00b_raw_linux_syscall1(SYS_exit, 0);
    __builtin_unreachable();
}

// Off-libc raw clone(2): NO glibc clone() wrapper, NO pthread.  The glibc
// wrapper runs glibc child-side trampoline code that assumes a libpthread
// thread; this lands the child directly in our entry with nothing between the
// syscall and n00b code.  Written as a normal function with register-pinned
// extended inline asm (the same pattern as _n00b_darwin_syscall, which ncc
// lowers fine) — NOT a naked function (ncc instruments bodies, which clang then
// rejects for naked) and NOT file-scope asm (ncc's parser does not accept it).
//
// The whole child path lives inside the asm and ends in a syscall, so the child
// NEVER falls back into C: only the parent reaches the C return.  The parent's
// ncc-inserted prologue/epilogue therefore run normally; the child runs none of
// them.  Returns the child tid (>0) in the parent, or a negative -errno on
// failure (raw-syscall convention: NOT -1/errno).
//
// Child register state after clone == the parent's at the syscall except the
// return value is 0 and SP is child_stack; all other regs are preserved, so the
// child reads fn/arg out of the registers we pinned them into.
static long
_n00b_os_raw_clone(unsigned long flags,
                   void         *child_stack,
                   int          *ptid,
                   int          *ctid,
                   void         *tls,
                   int (*fn)(void *),
                   void *arg)
{
#if defined(__aarch64__)
    // AArch64's legacy clone syscall wants flags/stack/ptid/tls/ctid in
    // x0..x4 and the number in x8.  This differs from x86-64's ctid/tls
    // ordering.  Keep the C helper signature architecture-neutral and load the
    // kernel registers in the architecture's order here; otherwise CLONE_SETTLS
    // can work while CLONE_CHILD_CLEARTID silently points at the wrong word.
    register long x0 __asm__("x0") = (long)(uintptr_t)flags;
    register long x1 __asm__("x1") = (long)(uintptr_t)child_stack;
    register long x2 __asm__("x2") = (long)(uintptr_t)ptid;
    register long x3 __asm__("x3") = (long)(uintptr_t)tls;
    register long x4 __asm__("x4") = (long)(uintptr_t)ctid;
    register long x5 __asm__("x5") = (long)(uintptr_t)fn;
    register long x6 __asm__("x6") = (long)(uintptr_t)arg;
    register long x8 __asm__("x8") = (long)SYS_clone;
    __asm__ volatile(
        "svc #0\n"
        "cbnz x0, 1f\n" // parent: x0 = child tid or -errno -> fall to C return
        "mov x0, x6\n"  // child: arg
        "blr x5\n"      // fn(arg) -> _n00b_linux_clone_entry, never returns
        "1:\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x8)
        : "memory", "cc", "x30");
    return x0;
#elif defined(__x86_64__)
    // Raw clone takes ctid in r10 (not rcx); the number goes in rax.  fn (r9)
    // and arg (r12, callee-saved so it survives the syscall) are read by the
    // child out of the registers — no child-stack stash needed.
    register long rax __asm__("rax") = (long)SYS_clone;
    register long rdi __asm__("rdi") = (long)(uintptr_t)flags;
    register long rsi __asm__("rsi") = (long)(uintptr_t)child_stack;
    register long rdx __asm__("rdx") = (long)(uintptr_t)ptid;
    register long r10 __asm__("r10") = (long)(uintptr_t)ctid;
    register long r8 __asm__("r8")   = (long)(uintptr_t)tls;
    register long r9 __asm__("r9")   = (long)(uintptr_t)fn;
    register long r12 __asm__("r12") = (long)(uintptr_t)arg;
    __asm__ volatile(
        "syscall\n"
        "testq %%rax, %%rax\n"
        "jnz 1f\n"            // parent -> fall to C return
        "movq %%r12, %%rdi\n" // child: arg
        "callq *%%r9\n"       // fn(arg) -> _n00b_linux_clone_entry, never returns
        "1:\n"
        : "+r"(rax)
        : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9), "r"(r12)
        : "memory", "cc", "rcx", "r11");
    return rax;
#else
#error "raw clone trampoline: add this architecture"
#endif
}

static int
_n00b_os_thread_create(n00b_callstack_t *cs, n00b_tbundle_t *bundle)
{
    // Allocate + seed the minimal TCB (one zeroed page, non-GC).  mach_port
    // is macOS-only; pass 0 on Linux.
    bundle->tcb = _n00b_tcb_alloc(0);
    if (bundle->tcb == nullptr) {
        return ENOMEM;
    }
    void *tls = _n00b_linux_clone_tls(bundle->tcb);
#if defined(__x86_64__)
    n00b_linux_tcbhead_t *tcb = (n00b_linux_tcbhead_t *)tls;
    tcb->tcb                  = tcb; // glibc's "[%fs:0] == self" invariant
#elif defined(__aarch64__)
    ((void **)tls)[0] = tls;
#endif

    // CLONE_CHILD_CLEARTID (WP-3a Phase 2, D-034): the kernel writes 0 to the
    // ctid word and futex-wakes it when the thread FULLY exits — the OS-death
    // edge the reaper gates callstack-pool return on.  Net-new this WP (the
    // prior flags did not request it).  Seed the word nonzero so a later 0 is
    // unambiguously the kernel's exit store, not the initial state.
    unsigned long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND
                        | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS
                        | CLONE_CHILD_CLEARTID;
    n00b_atomic_store(&bundle->child_tid, 1u);

    // Child stack grows down from below the ID word at the top of the
    // region (region_start + S - 8), 16-aligned, so the first frame cannot
    // clobber the identity word.
    void *child_sp = (void *)(((uintptr_t)cs->stack_high
                               - N00B_CALLSTACK_ID_WORD_SIZE)
                              & ~(uintptr_t)15);

#if defined(__GLIBC__)
    // Tell glibc the process is multithreaded BEFORE the child (or any
    // concurrent main-thread libc call) runs.  We spawn via raw clone(2), not
    // pthread_create, so glibc would otherwise keep __libc_single_threaded true
    // and elide its internal locks — letting two threads race inside stdio /
    // malloc / etc (wax#493: a worker's fprintf(stderr) vs the main thread's,
    // NULL-derefing the shared FILE buffer).  A plain relaxed store is correct:
    // it only ever transitions true -> false (never back), it is idempotent
    // across spawns, and setting it in the PARENT before the clone means glibc
    // already knows by the time the worker executes.  Matches what
    // pthread_create does internally.
    __libc_single_threaded = 0;
#endif

    // Raw clone(2) via our naked trampoline — NO glibc clone() wrapper, NO
    // pthread.  The child enters _n00b_linux_clone_entry directly.  CLONE_SETTLS
    // sets the kernel TLS register (arm64 TPIDR_EL0 / x86-64 %fs.base) to our
    // minimal TCB block (D-021); CLONE_CHILD_CLEARTID clears &bundle->child_tid
    // at exit (D-034).  Returns child tid (>0) or a negative -errno.
    long tid = _n00b_os_raw_clone(flags,
                               child_sp,
                               (int *)nullptr, // ptid (CLONE_PARENT_SETTID unset)
                               // ctid (CLONE_CHILD_CLEARTID): the kernel does a
                               // plain 32-bit store + futex wake here; cast away
                               // _Atomic for the pointer-type (our side reads it
                               // atomically).
                               (int *)&bundle->child_tid,
                               tls,                // CLONE_SETTLS value
                               _n00b_linux_clone_entry,
                               bundle);
    if (tid < 0) {
        _n00b_tcb_free(bundle->tcb);
        bundle->tcb = nullptr;
        return (int)-tid; // raw syscall returns -errno
    }
    return 0;
}

#elif defined(_WIN32)
// Windows: CreateThread, then RUN THE WORKER ON THE n00b CALLSTACK (D-023 W3
// CLOSED, D-025).  Win32 has no documented way to point CreateThread at
// caller-supplied stack memory (lpStackSize only sizes the kernel-owned
// stack; there is no stack-base parameter), so the kernel hands the new
// thread its own stack.  We therefore switch onto the n00b callstack at the
// very top of the entry trampoline: the kernel-provided stack carries only
// the trampoline's own frame, and we move SP into the S-aligned n00b region
// (cs) before calling n00b_thread_launcher.  After the switch the worker's SP
// lives inside `cs`, so n00b_thread_self()'s O(1) SP-mask branch recovers the region base
// and reads the ID word at base + S - 8 — identity resolves for Win32 workers
// exactly as it does on macOS/Linux.  (The n00b callstack is also the region
// n00b_capture_stack_base publishes as the worker's bounds via the
// thread->callstack early-return, so the bounds back-check in n00b_thread_self() agrees.)
//
// The stack switch is a tiny architecture-specific SP move done in inline
// asm: set SP to (cs->stack_high - ID_WORD_SIZE) 16-aligned (below the
// identity ID word at the top of the region, matching the macOS/Linux entry),
// then tail-call the launcher with the bundle in the first-arg register.  The
// launcher never returns on the worker before the join wake; on Win32 it does
// return (it does its own futex wake), after which the trampoline restores the
// kernel stack and returns from the thread normally.
//
// WRITTEN-ONLY on this host (the dev host is macOS): the Win32 stack-switch
// asm and CreateThread path are not compiled or executed here; they are
// host-verified by the user.  The SP-move sequences below follow the
// platform calling convention (x64: bundle in RCX; arm64: bundle in X0).
[[noreturn]] static void
_n00b_win_run_on_callstack(n00b_callstack_t *cs, n00b_tbundle_t *bundle)
{
    // SP starts below the identity ID word at the top of the region
    // (region_start + S - 8), 16-aligned, so the first frame cannot clobber
    // the identity word — the same geometry the macOS/Linux entry uses.
    uintptr_t sp = ((uintptr_t)cs->stack_high - N00B_CALLSTACK_ID_WORD_SIZE)
                 & ~(uintptr_t)15;

    // MSVCRT and Windows unwinding validate stack operations against the TEB
    // bounds.  After the manual RSP switch, this thread runs entirely on the
    // n00b callstack, so publish those bounds before entering code that can
    // call setjmp/longjmp or unwind through runtime helpers.
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
    if (tib != nullptr) {
        tib->StackLimit = cs->stack_low;
        tib->StackBase  = cs->stack_high;
    }

    // CONTRACT (Win32, written-only — host-verify): n00b_thread_launcher MUST
    // return normally here.  The call/blr below puts its return address on the
    // n00b callstack (SP has already been switched), and that is only safe
    // because ExitThread(0) terminates the thread WITHOUT unwinding past this
    // frame.  If the launcher's Win32 path ever exits via SEH or an abort that
    // unwinds, the unwinder would walk from the n00b callstack into the
    // abandoned kernel stack — so that path must stay free of frame-unwinding
    // exits.

#if defined(_M_X64) || defined(__x86_64__)
    // x64: bundle in RCX (Win64 first integer arg).  Move RSP onto the n00b
    // stack, reserve the 32-byte shadow space the Win64 ABI requires, then
    // call the launcher.  The launcher returns on Win32, so control comes
    // back here on the n00b stack; terminate the thread directly rather than
    // unwinding back onto the (now-abandoned) kernel stack.
    __asm__ volatile(
        "movq %0, %%rsp\n\t"
        "movq %1, %%rcx\n\t"
        "subq $32, %%rsp\n\t"
        "call *%2\n\t"
        :
        : "r"(sp), "r"(bundle), "r"(&n00b_thread_launcher)
        : "rcx", "memory");
#elif defined(_M_ARM64) || defined(__aarch64__)
    // arm64: bundle in X0.  Move SP onto the n00b stack and call the launcher.
    __asm__ volatile(
        "mov sp, %0\n\t"
        "mov x0, %1\n\t"
        "blr %2\n\t"
        :
        : "r"(sp), "r"(bundle), "r"(&n00b_thread_launcher)
        : "x0", "x30", "memory");
#else
#error "Win32 n00b-callstack switch: unsupported architecture"
#endif

    // The launcher returned (Win32 path); the worker is fully torn down and
    // any joiner has been woken.  We are on the n00b callstack, which the
    // REAPER reclaims at OS-confirmed death (WP-3a Phase 2 / D-034 — NOT the
    // joiner, which frees nothing; for custom_stack the caller owns the
    // pages); end the thread without unwinding onto the kernel stack we left
    // behind.
    ExitThread(0);
}

static DWORD WINAPI
_n00b_win_thread_entry(LPVOID raw)
{
    n00b_tbundle_t *bundle = (n00b_tbundle_t *)raw;
    // Switch onto the n00b callstack immediately, then run the launcher so the
    // worker's SP lives in the S-aligned region and n00b_thread_self() resolves.
    _n00b_win_run_on_callstack(bundle->callstack, bundle);
    return 0; // unreachable (the switch helper is [[noreturn]]).
}

static int
_n00b_os_thread_create(n00b_callstack_t *cs, n00b_tbundle_t *bundle)
{
    // The worker switches onto `cs` itself at entry (see
    // _n00b_win_run_on_callstack); the kernel-provided stack is used only for
    // the trampoline frame before the switch, so request a minimal one.
    (void)cs;
    HANDLE h = CreateThread(nullptr,
                            0,
                            _n00b_win_thread_entry,
                            bundle,
                            CREATE_SUSPENDED,
                            nullptr);
    if (h == nullptr) {
        return EAGAIN;
    }
    bundle->os_thread_handle = h;
    if (ResumeThread(h) == (DWORD)-1) {
        bundle->os_thread_handle = nullptr;
        CloseHandle(h);
        return EAGAIN;
    }
    return 0;
}

#else
#error "Don't know how to raw-create a thread on this platform"
#endif

n00b_result_t(n00b_thread_t *)
n00b_thread_spawn(void *(*fn)(void *), void *arg) _kargs
{
    n00b_string_t           *name           = nullptr;
    n00b_finalizer_t         finalizer      = nullptr;
    void                    *finalizer_data = nullptr;
    n00b_callstack_region_t *custom_stack   = nullptr;
    n00b_thread_tier_t       priority       = N00B_THREAD_TIER_DEFAULT;
    n00b_thread_tier_t       scheduler      = N00B_THREAD_TIER_DEFAULT;
    n00b_thread_sched_raw_t *sched_raw      = nullptr;
    n00b_thread_cpuset_t    *affinity       = nullptr;
    bool                     isolation      = false;
    n00b_thread_crash_handler_t crash_handler      = nullptr;
    void                       *crash_handler_data = nullptr;
}
{
    n00b_runtime_t *rt = n00b_get_runtime();
    if (!rt) return n00b_result_err(n00b_thread_t *, ENXIO);

    // Allocate the worker's OS callstack.  The worker runs on this region
    // (all platforms now, including Win32 — see the Win32 _n00b_os_thread_create
    // note) and writes its identity ID word into it at entry.  When the caller
    // supplied .custom_stack, lay the n00b geometry over THEIR pages instead
    // of allocating fresh ones (D-025); the resulting callstack carries
    // caller_owned = true so the reaper drops the registrations without
    // unmapping the caller's memory.  Otherwise draw a region from the
    // callstack pool (reusing a reaped worker's region) or allocate fresh on a
    // miss; the REAPER returns it to the pool at OS-death (D-034).
    // Reaper on the callstack-pool SLOW PATH (D-034): before we need a
    // callstack, sweep OS-dead workers back into the pool so this spawn can
    // recycle one of their 8 MiB regions instead of mmap'ing a fresh one.  The
    // sweep is bounded (one queue walk) and reclaims ONLY workers whose OS
    // death edge has fired.
    _n00b_reap_sweep(rt);

    n00b_result_t(n00b_callstack_t *) cs_r;
    if (custom_stack != nullptr) {
        // Caller-owned backing pages are never pooled — lay geometry over them
        // directly (the REAPER drops the registrations at OS-confirmed death
        // without unmapping the caller's pages — D-034; the joiner frees
        // nothing).
        cs_r = n00b_callstack_alloc_over(*custom_stack);
    }
    else {
        // Draw from the callstack pool (reuse a reaped region) or allocate
        // fresh on a pool miss (D-034).
        cs_r = n00b_callstack_pool_get();
    }
    if (n00b_result_is_err(cs_r)) {
        return n00b_result_err(n00b_thread_t *, n00b_result_get_err(cs_r));
    }
    n00b_callstack_t *callstack = n00b_result_get(cs_r);

    // WP-3b (D-039): draw a SECOND pool region for the worker's crash-handler
    // alternate signal stack.  It must be allocated HERE (the spawner), where
    // the calling thread's default allocator is live — a worker cannot allocate
    // its own at launch (its launch-time default allocator returns guard-band
    // memory) and per-slot-forever allocation explodes to N00B_THREADS_MAX * S
    // (the discarded D-038 model).  The reaper returns it to the pool at OS death
    // alongside `callstack`, so the live set is bounded.  Best-effort: a pool
    // miss/alloc failure leaves it null and the worker runs without an altstack
    // (the handler then runs on the faulting stack — fine except on a true
    // overflow), rather than failing the spawn.
    n00b_callstack_t *altstack = nullptr;
    {
        n00b_result_t(n00b_callstack_t *) as_r = n00b_callstack_pool_get();
        if (n00b_result_is_ok(as_r)) {
            altstack = n00b_result_get(as_r);
        }
    }

    // Pre-acquire a thread slot so the launcher can register into it
    // directly (the placeholder is replaced by the worker's init struct).
    n00b_thread_t *placeholder = N00B_THREAD_SLOT_PLACEHOLDER;
    uint32_t       slot        = n00b_thread_slot_acquire(rt, placeholder);

    // Allocate the bundle from system_pool (pinned, non-movable) rather
    // than the GC default arena.  Between the raw OS create and the
    // worker's call to n00b_thread_init(), the new thread holds `bundle`
    // in a register the GC's stack-scan cannot see (the thread isn't
    // registered yet).  If GC fires on another thread during that window
    // and moves the bundle in the default arena, the worker's register
    // copy goes stale.  The system_pool never moves, closing this race.
    n00b_tbundle_t *bundle = n00b_alloc_with_opts(
        n00b_tbundle_t,
        &(n00b_alloc_opts_t){.allocator = (n00b_allocator_t *)&rt->system_pool});
    if (!bundle) {
        n00b_atomic_store(&rt->threads[slot].thread, (n00b_thread_t *)nullptr);
        // The worker never started, so neither stack is live: return both to the
        // pool (a fresh/pool region) or drop the caller-owned registrations.
        n00b_callstack_pool_return(callstack);
        if (altstack != nullptr) {
            n00b_callstack_pool_return(altstack);
        }
        return n00b_result_err(n00b_thread_t *, ENOMEM);
    }

    bundle->fn               = fn;
    bundle->arg              = arg;
    bundle->tid              = slot;
    bundle->callstack        = callstack;
    bundle->altstack         = altstack;
    bundle->os_thread_handle = nullptr;
    bundle->name             = name;
    bundle->finalizer        = finalizer;
    bundle->finalizer_data   = finalizer_data;

    // Resolve the requested tier: `.priority` and `.scheduler` are two names
    // for the same normalized tier request, so take the higher of the two
    // (DEFAULT == 0 is the lowest enumerator, so a single set value wins and a
    // caller cannot accidentally downgrade by leaving one at default).  The
    // raw escape, when supplied, is copied and overrides the tier on apply.
    bundle->sched_tier    = (priority > scheduler) ? priority : scheduler;
    bundle->sched_raw_set = (sched_raw != nullptr);
    bundle->sched_raw     = (sched_raw != nullptr) ? *sched_raw
                                                   : (n00b_thread_sched_raw_t){};

    // Affinity (WP-002 Phase 4, D-025): copy the requested CPU-id set onto the
    // bundle (an empty set means none was requested).  The descriptor itself
    // need only live for the duration of this call.
    bundle->affinity      = (affinity != nullptr) ? *affinity
                                                  : (n00b_thread_cpuset_t){};

    // Isolation (WP-002 Phase 5, D-025 Q1): carry the flag to the launcher,
    // which sets it on the published struct so the GC excludes the worker's C
    // stack from the conservative scan.
    bundle->isolation     = isolation;

    // Crash-handler surface (WP-002 Phase 6, D-025 Q4): carry the registered
    // handler (+ data) to the launcher, which STORES them on the published
    // struct.  No signal handler / sigaltstack / delivery is wired here or in
    // the launcher — that is WP-3.
    bundle->crash_handler      = crash_handler;
    bundle->crash_handler_data = crash_handler_data;
    n00b_futex_init(&bundle->ready);

    int rc = _n00b_os_thread_create(callstack, bundle);
    if (rc != 0) {
        n00b_atomic_store(&rt->threads[slot].thread, (n00b_thread_t *)nullptr);
        // Create failed before any worker ran on either region: return BOTH to
        // the pool (or drop caller-owned registrations) rather than unmap regions
        // we could reuse.  The worker never installed bundle->altstack on a
        // struct, so the reaper will never see it — return it here (WP-3b/D-039).
        n00b_callstack_pool_return(callstack);
        if (altstack != nullptr) {
            n00b_callstack_pool_return(altstack);
        }
        return n00b_result_err(n00b_thread_t *, rc);
    }

    // Wait for the child to finish n00b_thread_init (so n00b_thread_self()/the slot
    // resolves before we return its n00b_thread_t * to the caller).  No
    // cooperative self-park around the wait (WP-001): a thread blocked in a
    // futex wait is preempted by the STW initiator, not self-parked.
    while (!n00b_atomic_load(&bundle->ready)) {
        n00b_futex_wait(&bundle->ready, 0, 100000000); // 100ms
    }

    // Read the child handle the worker published into the bundle (the bundle
    // is the stable system_pool scratch struct; the handle it carries is the
    // permanent user_pool n00b_thread_t — D-034), NOT rt->threads[slot].thread:
    // a short-lived worker may have already cleared the slot in
    // n00b_thread_destroy by now.
    n00b_thread_t *child = n00b_atomic_load(&bundle->self);

    return n00b_result_ok(n00b_thread_t *, child);
}

void *
n00b_thread_join(n00b_thread_t *thread)
{
    if (!thread) return nullptr;

    // Native (non-pthread) join: wait for the worker to publish "done"
    // into join_futex, then read its result.  No cooperative self-park around
    // the wait (WP-001): a joiner blocked in a futex wait is preempted by the
    // STW initiator, not self-parked.
    //
    // wait-then-recheck against the publish-then-wake on the worker side:
    // if the worker already stored 1 before we waited, n00b_futex_wait
    // returns immediately (value mismatch); otherwise we block until woken.
    while (n00b_atomic_load(&thread->join_futex) == 0) {
        n00b_futex_wait(&thread->join_futex, 0, 100000000); // 100ms
    }

    void *retval = n00b_atomic_load(&thread->join_result);

    // Join frees NOTHING (WP-3a Phase 2 / D-034).  Observing join_futex == 1 is
    // the worker's STILL-ON-STACK window: it has yet to run n00b_futex_wake +
    // (macOS) _n00b_worker_self_terminate.  The WP-1 join freed thread->callstack
    // / thread->tcb right here — a use-after-free that pooled reuse would make
    // catastrophic (a later spawn could hand the still-live stack to a new
    // worker).  Reclamation is now the REAPER's, gated on the OS-confirmed-death
    // edge (macOS dead Mach port / Linux CLONE_CHILD_CLEARTID futex): the worker
    // enqueued itself on rt->reap_pending before terminating, and the reaper
    // (callstack-pool slow path + conduit signal thread) returns the callstack
    // to the pool, frees the TCB, and deallocates the port only after the OS
    // says the worker is off its stack.  The n00b_thread_t struct is GC-owned
    // (user_pool, D-034) and is never freed here.  Join is RESULT-ONLY: it waits
    // and returns the worker's `void *` fn-return; the 64-bit exit code stays
    // readable via n00b_thread_exit_code (settled before the wake).
    //
    // A successful join transfers ownership back to the caller, and callers may
    // immediately drop the last explicit handle/root.  Do not return until the
    // OS-death reaper is done with the thread struct's callstack/altstack fields.
    // Otherwise the struct can become unreachable while rt->reap_pending (or a
    // detached sweep local) is still the only raw reference to it.
    n00b_runtime_t *rt = n00b_get_runtime();
    while (n00b_atomic_load(&thread->reap_futex) == 0) {
        _n00b_reap_sweep(rt);
        if (n00b_atomic_load(&thread->reap_futex) == 0) {
            n00b_futex_wait(&thread->reap_futex, 0, 10000000); // 10ms
        }
    }

    return retval;
}
