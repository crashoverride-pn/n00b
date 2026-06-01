#ifndef _WIN32
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#else
#include "core/platform.h"
#include <io.h>
#endif

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_act.h>
#include <mach/thread_policy.h>
#include <sys/syscall.h>
#endif

#if defined(__linux__)
#include <sched.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
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
#include "core/stw.h"

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
    uint32_t       candidate;
    n00b_thread_t *expected;

    do {
        candidate = n00b_atomic_add(&rt->next_thread_slot, 1);
        candidate %= rt->max_threads;
        expected = nullptr;
    } while (!n00b_cas(&rt->threads[candidate].thread, &expected, ptr));

    return candidate;
}

void
n00b_thread_init() _kargs
{
    n00b_runtime_t *runtime            = n00b_get_runtime();
    uint32_t acquired_slot             = 0;
    struct n00b_callstack_t *callstack = nullptr;
}
{
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
    init_self.gc_stack_top    = _n00b_bootstrap_thread.gc_stack_top;
    init_self.gc_stack_policy = _n00b_bootstrap_thread.gc_stack_policy;
    // Record the worker's callstack on the init-scoped struct BEFORE the
    // first allocation: n00b_thread_self()'s worker-masking branch back-verifies the
    // resolved thread's callstack->region_start against the masked SP base,
    // so a worker must carry its callstack from the very first n00b_thread_self() (the
    // GC-stack push around the permanent-struct alloc below).  Null for the
    // main thread, which resolves via the range check instead.
    init_self.callstack = (n00b_callstack_t *)callstack;

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

    init_self.record                   = rec;
    init_self.id_info.parts.id         = (int32_t)acquired_slot;
    init_self.id_info.parts.generation = (int32_t)gen;

    // Publish bounds + the init self pointer so n00b_thread_self() resolves for this
    // thread during the permanent-struct allocation below.  capture_base
    // writes rec->stack_lo/hi (stack_hi first, stack_lo last as the gate).
    n00b_capture_stack_base(&init_self, runtime);
    n00b_capture_stack_top(&init_self);

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

    // Repoint the slot at the permanent struct.  After this store, n00b_thread_self()
    // resolves (main: range check; worker: bounds scan) to `self`.
    n00b_atomic_store(&rec->thread, self);

    n00b_atomic_add(&runtime->live_threads, 1);
    n00b_futex_wake((n00b_futex_t *)&rec->thread, true);
}

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

        lock = next;
    }
    n00b_atomic_store(&rec->exclusive_locks, nullptr);

    // Walk read locks and release each one.
    n00b_thread_read_log_t *rlog = n00b_atomic_load(&rec->read_locks);

    while (rlog) {
        n00b_thread_read_log_t *next = rlog->next_entry;
        n00b_rwlock_t          *rw   = rlog->obj;

        if (rw && rlog->level > 0) {
            // Decrement the reader count.
            uint32_t value, desired;
            do {
                value   = n00b_atomic_load(&rw->futex);
                desired = value - 1;
            } while (!n00b_cas(&rw->futex, &value, desired));
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

    n00b_thread_record_t *rec = self->record;

    if (rec) {
        // If this thread is on a CV's waiters list, remove it.
        n00b_condition_t *cv = rec->cv_info.current_cv;
        if (cv) {
            (void)n00b_list_remove_all(cv->waiters, self);
            rec->cv_info.current_cv = nullptr;
        }

        n00b_release_locks_on_thread_exit(rec);
        n00b_atomic_or(&self->self_lock, N00B_SUSPEND);

        // Retire this worker's stack-bounds advertisement BEFORE clearing
        // the slot.  n00b_thread_self()'s worker bounds-scan matches an SP
        // against every slot's published [stack_lo, stack_hi); once this
        // worker exits its callstack is freed and its address range can be
        // handed to a LATER worker's callstack.  If the dead slot kept
        // advertising that range (with rec->thread now null), the scan would
        // match the dead slot first and resolve n00b_thread_self() to null for the new
        // worker — crashing it (n00b_capture_stack_top on a null self).
        // Clear stack_lo first (it is the release gate the scan loads first;
        // a null gate makes the scan skip this slot), then stack_hi.
        if (self->callstack != nullptr) {
            n00b_atomic_store(&rec->stack_lo, (void *)nullptr);
            n00b_atomic_store(&rec->stack_hi, (void *)nullptr);
        }

        n00b_atomic_store(&rec->thread, nullptr);
    }

    if (self->memperm_pipe.ready) {
#ifdef _WIN32
        _close(self->memperm_pipe.fds[0]);
        _close(self->memperm_pipe.fds[1]);
#else
        close(self->memperm_pipe.fds[0]);
        close(self->memperm_pipe.fds[1]);
#endif
    }

    n00b_runtime_t *rt = n00b_get_runtime();
    if (rt) {
        // Unregister the stack region from the mmap tree.  For the MAIN
        // thread, self->stack_map is its own registration (made in
        // n00b_capture_stack_base) and this is the only place it is torn
        // down.  For a raw WORKER, self->stack_map aliases its callstack's
        // registration (cs->stack_map) — owned by the callstack reclamation
        // path (n00b_callstack_pool_return / n00b_callstack_free), which the
        // REAPER drives at OS-confirmed death (WP-3a Phase 2 / D-034 — NOT the
        // joiner, which under D-034 frees nothing) — so unregistering it here
        // too would double-delete the same interval-tree node and corrupt the
        // tree (surfaces as an n00b_mmaps_detach_base / detach_ranges assert at
        // shutdown).  A worker is identified by carrying a callstack; skip the
        // unregister for it and leave the region to the reaper.
        if (self->stack_map && self->callstack == nullptr) {
            n00b_mmap_unregister((void *)self->stack_map->start);
            self->stack_map = nullptr;
        }

        n00b_atomic_add(&rt->live_threads, -1);
        n00b_futex_wake((n00b_futex_t *)&rt->live_threads, true);
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
n00b_capture_stack_base(n00b_thread_t *thread, n00b_runtime_t *runtime)
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
    // On Windows, use the Thread Environment Block for all threads.
    (void)runtime;
    {
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
        // After WP-001 Phase 3 every worker runs on an n00b callstack and
        // is handled by the `thread->callstack != nullptr` early-return
        // above, so this branch is reached only by a non-main, non-callstack
        // thread — which the n00b thread lifecycle no longer creates (raw
        // creation replaced pthread_create; the residual VFS frontend
        // pthreads run OUTSIDE this lifecycle and never call
        // n00b_capture_stack_base).  The old Phase-2 transitional pthread
        // stack query (pthread_getattr_np / pthread_attr_getstack /
        // pthread_self / pthread_get_stackaddr_np) lived here and was deleted
        // with the WP-001 pthread excision (D-002/D-009): main-thread
        // discovery is OS-native (above) and workers self-describe via their
        // callstack.  Leaving the bounds zeroed is the correct behaviour for
        // an unexpected caller; there is no pthread fallback by design.
        lowest  = nullptr;
        highest = nullptr;
        size    = 0;
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

    thread->stack_map = n00b_option_get(
        n00b_mmap_register(lowest, highest, n00b_mmap_stack));
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
static void *
_n00b_tcb_alloc(uint32_t mach_port)
{
    auto map_r = n00b_check_mmap(nullptr,
                                 (size_t)n00b_page_size,
                                 N00B_MPROT,
                                 N00B_MFLAG,
                                 -1,
                                 0);
    if (n00b_result_is_err(map_r)) {
        return nullptr;
    }
    void *tcb = n00b_result_get(map_r);

#ifdef __APPLE__
    // Seed the platform-ABI slots os_unfair_lock / errno read.  The page is
    // already kernel-zeroed, so every other slot reads as a benign 0.
    uint64_t *slots                       = (uint64_t *)tcb;
    slots[N00B_TSD_SLOT_THREAD_SELF]      = (uint64_t)(uintptr_t)tcb;
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
        n00b_safe_munmap(tcb, (size_t)n00b_page_size);
    }
}
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
    (void)syscall(SYS_sched_setscheduler, 0, policy, &param);
    if (policy == N00B_SCHED_OTHER || policy == N00B_SCHED_BATCH
        || policy == N00B_SCHED_IDLE) {
        // nice is set via setpriority on the calling thread (who == 0).
        (void)syscall(SYS_setpriority, N00B_PRIO_PROCESS, 0, nice_value);
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
        uint64_t *slots = (uint64_t *)self->tcb;
        mp              = (mach_port_t)slots[N00B_TSD_SLOT_MACH_THREAD_SELF];
    }
    if (mp == MACH_PORT_NULL) {
        return; // cannot recover the port; fail-soft.
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
        uint64_t *slots = (uint64_t *)self->tcb;
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
    (void)syscall(SYS_sched_setaffinity, 0, sizeof(unsigned long), &kmask);
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
        // No port recorded (e.g. main thread shouldn't be here); treat as
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
#else
    // Win32 workers return from the launcher and ExitThread() on the kernel
    // stack; the n00b callstack is no longer in use once the launcher returned.
    // (Win32 reclamation is host-verified later; treat as dead so the region
    // recycles.)
    return true;
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
void
n00b_thread_reap_pending(void)
{
    _n00b_reap_sweep(n00b_get_runtime());
}

// Common worker prologue/epilogue, shared by every platform's raw entry
// trampoline.  The trampoline (per OS) sets up the C environment and
// jumps here with the bundle in hand.  This function must keep the
// worker resolvable via n00b_thread_self() at every allocating call (it writes the
// id word first) and must never return on macOS (the caller terminates
// the Mach thread itself).
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
    _n00b_darwin_set_thread_pointer(bundle->tcb);
#endif

    // Identity FIRST: write our slot id into the callstack ID word so the
    // very next n00b_thread_self() (emitted by the codegen's GC-stack push around the
    // first allocation in n00b_thread_init) resolves to this thread.
    _n00b_worker_write_id_word(bundle->callstack, bundle->tid);

    n00b_thread_init(.runtime       = rt,
                     .acquired_slot = bundle->tid,
                     .callstack     = bundle->callstack);

    n00b_thread_t *self = n00b_thread_self();
    n00b_capture_stack_top(self);

    n00b_crash_install_altstack(bundle->altstack); // WP-3b (D-039)

    // Record the TCB on the permanent thread struct so the REAPER can unmap
    // it after this worker exits (the worker must not free its own TSD while
    // still running on it).  Reclamation moved off the joiner onto the
    // OS-death edge (WP-3a Phase 2, D-034).
    self->tcb = bundle->tcb;

    // Record the OS-death-edge liveness primitive on the published struct so
    // the reaper can test this worker's true death (WP-3a Phase 2, D-034).
    // macOS: the Mach thread port (self-terminated worker -> thread_info fails).
    // Linux: seed the CLONE_CHILD_CLEARTID child-tid word nonzero so a later 0
    // (written by the kernel at true exit) is the unambiguous death signal; the
    // clone() ctid argument already points at self->child_tid (set by the
    // spawner before create).
    self->os_thread_port = bundle->os_thread_port;
#if defined(__linux__)
    // Record the address of the CLONE_CHILD_CLEARTID word (in the stable
    // bundle) so the reaper can observe the kernel's exit-time 0 store via
    // self.  Written-complete; Docker-verified later (D-026/D-028).
    self->child_tid_word = &bundle->child_tid;
    // WP-4 (D-040): record this worker's OS tid (resolves to the caller's own
    // tid here, on the worker) so the STW initiator can tgkill the preemptive
    // suspend signal at it.  Raw SYS_gettid — no libc wrapper.
    self->os_tid = (uint32_t)syscall(SYS_gettid);
#elif defined(_WIN32)
    // WP-4 (D-040): record this worker's Windows thread id so the STW initiator
    // can OpenThread + SuspendThread it.
    self->os_tid = (uint32_t)GetCurrentThreadId();
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

    n00b_thread_destroy();

    // Enqueue ourselves on the runtime reap-pending queue BEFORE the join
    // publish-then-wake and self-terminate (WP-3a Phase 2, D-034).  The
    // reaper drains this queue and reclaims our callstack/TCB/slot ONLY once
    // the OS confirms we are off this stack (macOS dead Mach port / Linux
    // CLONE_CHILD_CLEARTID futex) — never at the join_futex handshake, which
    // is exactly this still-on-stack window.  Enqueuing here (still on the
    // stack) is safe: the reaper gates on the death edge, not on queue
    // presence, so it will not reclaim until after _n00b_worker_self_terminate.
    _n00b_reap_enqueue(rt, self);

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
    syscall(SYS_exit, 0);
    __builtin_unreachable();
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
    n00b_linux_tcbhead_t *tcb = (n00b_linux_tcbhead_t *)bundle->tcb;
    tcb->tcb                  = tcb; // glibc's "[%fs:0] == self" invariant

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

    // glibc's clone() wrapper takes (fn, child_stack, flags, arg, [ptid, tls,
    // ctid]).  We call it directly rather than via SYS_clone so the child
    // returns into _n00b_linux_clone_entry cleanly across architectures (the
    // raw syscall returns 0 in the child IN the parent's frame, which is
    // fragile).  CLONE_SETTLS makes the kernel set %fs.base to our TCB head
    // (D-021); CLONE_CHILD_CLEARTID makes it clear &bundle->child_tid at exit
    // (D-034) — the ctid argument is the variadic tail after the tls pointer.
    long tid = clone(_n00b_linux_clone_entry,
                     child_sp,
                     (int)flags,
                     bundle,
                     (pid_t *)nullptr, // ptid (CLONE_PARENT_SETTID not set)
                     bundle->tcb,      // tls
                     &bundle->child_tid); // ctid (CLONE_CHILD_CLEARTID)
    if (tid == -1) {
        int e = errno;
        _n00b_tcb_free(bundle->tcb);
        bundle->tcb = nullptr;
        return e;
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
                            0,
                            nullptr);
    if (h == nullptr) {
        return EAGAIN;
    }
    CloseHandle(h);
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
    n00b_thread_t *placeholder = (n00b_thread_t *)(uintptr_t)1;
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

    bundle->fn             = fn;
    bundle->arg            = arg;
    bundle->tid            = slot;
    bundle->callstack      = callstack;
    bundle->altstack       = altstack;
    bundle->name           = name;
    bundle->finalizer      = finalizer;
    bundle->finalizer_data = finalizer_data;

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
    // resolves before we return its n00b_thread_t * to the caller).
    while (!n00b_atomic_load(&bundle->ready)) {
        n00b_stw_suspend_ctx stw_ctx = {0};

        n00b_thread_suspend(stw_ctx);
        n00b_futex_wait(&bundle->ready, 0, 100000000); // 100ms
        n00b_thread_resume(stw_ctx);
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
    // into join_futex, then read its result.  Keep the STW suspend/resume
    // bracketing so the blocking wait composes with the (not-yet-
    // redesigned) cooperative STW — a joiner parked in n00b_futex_wait
    // must look suspended to a stop-the-world initiator.
    n00b_stw_suspend_ctx stw_ctx = {0};

    n00b_thread_suspend(stw_ctx);
    // wait-then-recheck against the publish-then-wake on the worker side:
    // if the worker already stored 1 before we waited, n00b_futex_wait
    // returns immediately (value mismatch); otherwise we block until woken.
    while (n00b_atomic_load(&thread->join_futex) == 0) {
        n00b_futex_wait(&thread->join_futex, 0, 100000000); // 100ms
    }
    n00b_thread_resume(stw_ctx);

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
    // Nudge the reaper so a joined worker's resources are reclaimed promptly
    // once its death edge fires (the worker may already be terminating).  This
    // is best-effort: if its death edge has not fired yet it stays queued and
    // the signal-thread backstop / a later spawn reclaims it.
    _n00b_reap_sweep(n00b_get_runtime());

    return retval;
}
