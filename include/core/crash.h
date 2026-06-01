/**
 * @file crash.h
 * @brief WP-3b crash detection/delivery + guard-page stack-overflow handler.
 *
 * On a fault (SIGSEGV/SIGBUS, or a Windows access violation), a process-global
 * handler classifies the faulting address — a hit on a worker's registered
 * PROT_NONE guard band is a stack overflow; anything else is a generic invalid
 * access — invokes the faulting thread's WP-2 `crash_handler` (if any), then
 * ABORTS (never resumes the faulting context — D-032 Q3).
 *
 * The handler runs in signal context, so its hot path is async-signal-safe:
 * it classifies via the per-thread cached `[guard_lo, guard_hi)` range
 * (thread.h) — NO mmap-registry lock — and resolves the faulting thread by
 * matching its alternate-signal-stack range, NOT by n00b_thread_self() (which
 * masks the SP to the callstack region and would not resolve on the altstack).
 */
#pragma once

#include "n00b.h"

// Forward declaration: this header is pulled in via the n00b.h umbrella before
// core/callstack.h, but n00b_crash_install_altstack takes a callstack region.
// The full definition lives in core/callstack.h; the redundant typedef is
// harmless (identical) under C11+.
typedef struct n00b_callstack_t n00b_callstack_t;

/**
 * @brief Install @p as_cs as the calling thread's alternate signal stack.
 *
 * The altstack is a full n00b CALLSTACK region (S-aligned, with the SP-mask
 * geometry), NOT a small fixed buffer: the handler is ncc-GC-instrumented, so
 * its prologue calls `n00b_thread_self()` and must run where `self()` resolves.
 * This routine stamps @p as_cs's ID word with the CALLING thread's slot id (so
 * `self()` resolves to it when the handler runs there), publishes it on the
 * per-worker `n00b_thread_t` (`self->altstack`, which the handler's range-scan
 * reaches via `rt->threads[i].thread->altstack` to find the faulting thread),
 * and hands the usable span to `sigaltstack`.
 *
 * It does NOT allocate: @p as_cs is drawn from the shared callstack pool by the
 * spawner (a worker, via the bundle) or by `n00b_crash_init` (the main thread),
 * and returned to that pool at OS-confirmed death by the reaper — the SAME
 * bounded lifetime as the worker's primary callstack (D-039, superseding the
 * per-slot-forever model of D-038). Allocating here is not viable: a worker's
 * launch-time default allocator returns guard-band memory, and a per-slot region
 * that is never freed explodes to N00B_THREADS_MAX * S.
 *
 * Best-effort: a nullptr @p as_cs (pool/alloc failure upstream) leaves the
 * thread without an altstack (the handler then runs on the faulting stack — fine
 * except on a true stack overflow). No-op on Windows (VEH has no altstack).
 */
extern void n00b_crash_install_altstack(n00b_callstack_t *as_cs);

/**
 * @brief Install the process-global crash (fault) handler.
 *
 * Installs a SIGSEGV/SIGBUS handler (`SA_SIGINFO | SA_ONSTACK`) and the main
 * thread's alternate signal stack. Called once, late in n00b_init (after the
 * mmap/thread machinery is up). On a fault the handler classifies the address
 * (a hit on a worker's guard band ⇒ stack overflow; else ⇒ invalid access),
 * invokes the faulting thread's `crash_handler` if registered, then aborts
 * (never resumes — D-032 Q3). No-op on Windows (a VEH path is written-only).
 */
extern void n00b_crash_init(void);
