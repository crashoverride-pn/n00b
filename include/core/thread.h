/**
 * @file thread.h
 * @brief Thread management and per-thread state.
 *
 * Defines the n00b_thread_t structure, the TLS-free n00b_thread_self() recovery
 * entry point, and helpers for capturing stack bounds (needed by the
 * GC).
 *
 * Per D-004/D-014, the calling thread's n00b_thread_t no longer lives
 * in `thread_local` storage; its canonical home is the permanent
 * n00b_thread_t allocated from the GC-visible, non-moving `user_pool`
 * (WP-3a / D-034) and pointed at by `rt->threads[slot].thread`.  Being a
 * pool it is non-moving (so `n00b_thread_self()` and the raw slot pointer
 * stay valid), but unlike the old `system_pool` home it is GC-OWNED —
 * reclaimed once unreferenced, not bulk-freed at teardown.
 * `n00b_thread_self()` recovers the slot from the current stack
 * pointer in O(1): a range check against the main thread's kernel-stack
 * bounds (stored in its `n00b_thread_record_t` at init), then the
 * Phase-1 masking helper `n00b_callstack_id_word` for worker callstacks.
 */
#pragma once

#include "n00b.h"
#include "core/rt_access.h"
#include "core/atomic.h"
#include "core/callstack.h"
#include "adt/option.h"
#include "adt/result.h"

/**
 * @brief Slot index reserved for the main (kernel-stack) thread.
 *
 * The main thread is the first to call `n00b_thread_init`, so it
 * acquires slot 0.  `n00b_thread_self()`'s O(1) range-check branch
 * reads the main-stack bounds from this slot's record (D-014).
 */
#define N00B_MAIN_THREAD_SLOT ((uint32_t)0)

/**
 * @brief Bootstrap thread struct used during the startup window.
 *
 * Serves `n00b_thread_self()` after the runtime exists but before the
 * main thread's slot bounds are published (init is single-threaded, so
 * a single non-moving struct is safe).  Defined in thread.c; declared
 * here because the `n00b_thread_self()` macro references it from every
 * translation unit.
 */
extern n00b_thread_t _n00b_bootstrap_thread;

typedef struct {
    int     fds[2]; // 0 is read end, 1 is write end
    uint8_t ready;
} n00b_memperm_pipe_t;

/**
 * @brief Per-thread state for condition variable waits.
 *
 * Defined here (rather than in condition.h) so that
 * `n00b_thread_record_t` can embed it by value without a
 * circular include dependency.
 */
struct n00b_condition_thread_state_t {
    _Atomic(n00b_condition_t *) current_cv;
    uint64_t                    wait_predicate;
    void                       *thread_param;
    char                       *wait_loc;
};

/**
 * @brief Per-thread shared record allocated from the system pool.
 *
 * Lives in `rt->threads[]` so that *other* threads can walk lock
 * chains on crash or thread-exit cleanup.  The owning thread
 * accesses this through `n00b_thread_t::record`.
 */
struct n00b_thread_record_t {
    _Atomic(n00b_thread_t *)          thread;          ///< Back-pointer to the runtime-owned thread_t.
    uint32_t                          generation;      ///< Generation counter for slot reuse.
    _Atomic(n00b_lock_base_t *)       exclusive_locks; ///< Head of exclusive-lock chain.
    _Atomic(n00b_thread_read_log_t *) read_locks;      ///< Head of read-lock chain.
    _Atomic(n00b_thread_read_log_t *) log_alloc_cache; ///< Cached freed read-log entries.
    n00b_condition_thread_state_t     cv_info;         ///< Condition-variable wait state.
    n00b_lock_base_t                 *lock_wait_target;///< Lock we are currently blocked on.
    char                             *lock_wait_loc;   ///< Source location of the wait.
    char                             *lock_wait_trace; ///< Backtrace at wait (debug).
    n00b_string_t                    *regex_last_detail; ///< Last regex compile error detail (per-thread).
    /* Main-thread kernel-stack bounds for the O(1) n00b_thread_self() range check
     * (D-014).  Populated only for the main thread's record
     * (N00B_MAIN_THREAD_SLOT); zero on worker records, which resolve via
     * the masking helper instead.  `stack_lo` is the lowest in-stack
     * address, `stack_hi` is one past the highest.  Written once by the
     * owning thread at init (stack_hi first, stack_lo last so a non-null
     * stack_lo implies stack_hi is set); read by n00b_thread_self()'s range check on
     * any thread. */
    _Atomic(void *)                   stack_lo;
    _Atomic(void *)                   stack_hi;
};

/**
 * @brief Normalized, cross-platform thread scheduling tier (WP-002, D-025).
 *
 * A small ordered set of OS-agnostic tiers a caller asks for via
 * `n00b_thread_spawn(.priority = …)` / `.scheduler = …`.  The launcher maps
 * the requested tier to each OS's native scheduling primitive on the worker
 * itself (no pthread; D-002/D-009):
 *
 *   - macOS: Mach `thread_policy_set(THREAD_PRECEDENCE_POLICY)` with a signed
 *     `importance` (idle → -2 … realtime → +2).  Precedence is the queryable
 *     Mach surface (`thread_policy_get` reads it back); it is best-effort by
 *     construction and never fails the spawn.
 *   - Linux: raw `sched_setscheduler(SCHED_*)` + `setpriority(nice)` on the
 *     calling thread (NOT `pthread_setschedparam`):
 *       idle      → SCHED_IDLE,  nice +19
 *       low       → SCHED_OTHER, nice +10
 *       normal    → SCHED_OTHER, nice  0
 *       high      → SCHED_OTHER, nice -10
 *       realtime  → SCHED_FIFO,  rt-priority 10
 *   - Win32: `SetThreadPriority` (idle → THREAD_PRIORITY_IDLE, low → BELOW,
 *     normal → NORMAL, high → ABOVE, realtime → TIME_CRITICAL).
 *
 * `.priority` and `.scheduler` are TWO NAMES for the SAME tier request (the
 * normalized model folds policy + priority into one ordered tier); passing
 * both is allowed and the launcher uses the higher of the two so a caller
 * cannot accidentally downgrade by setting one and leaving the other at the
 * default.  The exact per-OS mapping is NOT 1:1 and is documented above.
 *
 * FAIL-SOFT (D-025): a privileged tier the process cannot grant (e.g.
 * `N00B_THREAD_TIER_REALTIME` without CAP_SYS_NICE on Linux) does NOT fail
 * the spawn — the worker runs at whatever the OS granted and the REQUESTED
 * tier is still recorded on `n00b_thread_t::sched_tier` for introspection.
 */
typedef enum : uint8_t {
    N00B_THREAD_TIER_DEFAULT  = 0, ///< No tier requested (leave OS default).
    N00B_THREAD_TIER_IDLE     = 1, ///< Run only when nothing else wants the CPU.
    N00B_THREAD_TIER_LOW      = 2, ///< Below-normal, still time-shared.
    N00B_THREAD_TIER_NORMAL   = 3, ///< The default time-shared tier.
    N00B_THREAD_TIER_HIGH     = 4, ///< Above-normal, still time-shared.
    N00B_THREAD_TIER_REALTIME = 5, ///< Highest; privileged on most OSes (fails soft).
} n00b_thread_tier_t;

/**
 * @brief Raw, per-OS scheduling escape hatch for platform-aware callers.
 *
 * When a caller passes `n00b_thread_spawn(.sched_raw = &(…){…})`, the launcher
 * BYPASSES the @ref n00b_thread_tier_t mapping entirely and applies these
 * values directly to the per-OS primitive on the worker (D-025).  The fields
 * are n00b-owned `int64_t`s (NOT a libc `struct sched_param` — no libc type
 * leaks into the public surface, D-002/D-009); each OS interprets them:
 *
 *   - Linux: `policy` is the `SCHED_*` constant for raw `sched_setscheduler`;
 *     `priority` is the rt-priority for the SCHED_FIFO/RR policies, or the
 *     `nice` value (via raw `setpriority`) for SCHED_OTHER/BATCH/IDLE.
 *   - macOS: `policy` selects the Mach policy flavor.  In WP-2 ONLY
 *     `THREAD_PRECEDENCE_POLICY` is honored — the `priority` field is applied
 *     as the signed `importance` under PRECEDENCE; any other `policy` value is
 *     NOT given its own Mach flavor (e.g. TIME_CONSTRAINT is a future
 *     extension).  The apply is fail-soft regardless, so a non-PRECEDENCE
 *     request never fails the spawn.
 *   - Win32: `policy` is unused; `priority` is the `SetThreadPriority` level.
 *
 * Like the tier path, the raw apply FAILS SOFT: an ungrantable request leaves
 * the worker at the OS default and the spawn still succeeds.  The descriptor
 * itself need only live for the duration of the spawn call (it is copied onto
 * the bundle); the applied values are recorded on
 * `n00b_thread_t::sched_raw` for introspection.
 */
typedef struct {
    int64_t policy;   ///< Per-OS policy selector (see per-OS notes above).
    int64_t priority; ///< Per-OS priority / importance / nice value.
} n00b_thread_sched_raw_t;

/**
 * @brief CPU-id set for thread affinity (WP-002 Phase 4, D-025).
 *
 * A caller asks for a worker's CPU affinity via
 * `n00b_thread_spawn(.affinity = &(n00b_thread_cpuset_t){.mask = …})`.  The set
 * is a FIXED 64-bit bitmask: bit `n` set means "CPU `n` is in the set" (so this
 * representation addresses logical CPUs 0..63; see the >64-CPU note below).
 * The launcher applies the set to the worker ITSELF (no pthread; D-002/D-009),
 * with per-OS strength:
 *
 *   - Linux: HARD PIN via raw `sched_setaffinity(0, sizeof(unsigned long),
 *     &mask)` (tid 0 = self) — NOT `pthread_setaffinity_np`, and WITHOUT
 *     glibc's `cpu_set_t`/`CPU_SET` macros: the @ref mask word IS the raw
 *     kernel cpu-set (one `unsigned long` on LP64, low bit = CPU 0), so it is
 *     handed to the syscall directly with `cpusetsize = sizeof(unsigned long)`.
 *   - Win32: HARD PIN via `SetThreadAffinityMask(GetCurrentThread(), mask)` —
 *     the `DWORD_PTR` mask is the @ref mask word truncated to pointer width.
 *   - macOS: ADVISORY ONLY.  Darwin exposes no hard CPU pin to user space; the
 *     launcher applies Mach `thread_policy_set(THREAD_AFFINITY_POLICY)` with an
 *     `affinity_tag` DERIVED from the set (the 1-based index of the lowest set
 *     CPU, so workers requesting the same lowest CPU share an L2-affinity tag).
 *     This is a SCHEDULER HINT, not a pin — the kernel may run the worker on
 *     any CPU (THREAD_AFFINITY_POLICY is documented "experimental" and a hint).
 *     Tests MUST NOT assert a hard pin on macOS (D-025 Q2b).
 *
 * An EMPTY set (`mask == 0`) requests no affinity and is treated as "leave the
 * OS default" on every platform (no syscall is made).  Like the scheduling
 * attributes, the apply is best-effort: a failed `sched_setaffinity` /
 * `SetThreadAffinityMask` (e.g. a mask naming no online CPU) is IGNORED and the
 * worker keeps running; the REQUESTED set is still recorded on
 * @ref n00b_thread_t::affinity for introspection.
 *
 * NUMA CO-LOCATION IS DEFERRED (D-025 Q2c): WP-002 does NOT parse
 * `/sys/devices/system/node` topology or place a worker on a NUMA node.  A
 * caller that wants NUMA locality MEANWHILE expresses it through this CPU-id
 * set — pin the worker to the CPU(s) of the desired node.  A dedicated NUMA API
 * is roadmap-tracked for a later WP, not part of this surface.
 *
 * >64-CPU NOTE: the fixed 64-bit mask addresses logical CPUs 0..63.  Machines
 * with more than 64 CPUs are not addressable above CPU 63 through this type; a
 * growable cpu-set is a possible future widening (the raw Linux syscall already
 * takes a `cpusetsize`, so the kernel side scales) but is NOT implemented in
 * WP-002 (DF-5, recorded for the orchestrator).
 */
typedef struct {
    uint64_t mask; ///< Bit `n` set ⇒ CPU `n` is in the set; 0 = no affinity.
} n00b_thread_cpuset_t;

/**
 * @brief Per-thread crash-handler callback (WP-002 Phase 6 SURFACE, D-025 Q4).
 *
 * A caller registers one via `n00b_thread_spawn(.crash_handler = …)`.  WP-002
 * STORES the handler (and its opaque data) on the worker's @ref n00b_thread_t
 * and DOES NOTHING ELSE with it — there is intentionally NO signal handler,
 * NO `sigaltstack`, and NO delivery path in WP-002.  Crash DELIVERY and the
 * guard-page SIGSEGV handler that will eventually INVOKE this callback are
 * DEFERRED TO WP-3.  The signature is the storage shape WP-3 will deliver to:
 * the crashing worker's own @ref n00b_thread_t (so the handler can recover
 * identity / the held-lock chains without relying on a faulting `n00b_thread_self()`) plus
 * the opaque @ref n00b_thread_t::crash_handler_data the caller registered.
 *
 * It is a plain function pointer (fits in `sizeof(void *)`) and a `void *` —
 * no libc type leaks into the public surface (D-002/D-009).
 *
 * @pre WP-3b DELIVERY (now live): this callback is invoked from the SIGSEGV/
 *      SIGBUS signal handler (on the alternate signal stack), so it MUST be
 *      async-signal-safe — no locking, no allocation, no non-AS-safe libc
 *      (stdio, etc.); the process aborts immediately after it returns (D-032
 *      Q3), so it cannot resume or repair the fault.  A non-AS-safe handler may
 *      deadlock (e.g. against a lock the faulting thread already held).
 */
typedef void (*n00b_thread_crash_handler_t)(n00b_thread_t *thread,
                                            void          *data);

struct n00b_thread_t {
    union {
        struct {
            int32_t id;
            int32_t generation;
        } parts;
        uint64_t unique_id;
    } id_info;

    void                 *stack_base;
    void                 *stack_top;
    n00b_mmap_info_t     *stack_map;
    _Atomic(void *)       guard_lo;   ///< Worker callstack guard-band low bound (nullptr for the main thread, which has no n00b guard band). Cached here so the WP-3b crash handler classifies a stack-overflow fault by a lock-free pointer-range compare (async-signal-safe; D-032 Q1 / WP-3b DF-3). _Atomic because the handler reads it cross-thread (matching stack_lo/stack_hi); the owning thread stores it once before its altstack install.
    _Atomic(void *)       guard_hi;   ///< Worker callstack guard-band high bound (exclusive); see @ref guard_lo.
    n00b_memperm_pipe_t   memperm_pipe;
    n00b_futex_t          self_lock;
    n00b_futex_t          cv_wake;      ///< Per-thread futex for CV notification.
    struct n00b_gc_stack_frame_t *gc_stack_top; ///< Top compiler-published exact GC frame.
    uint32_t              gc_stack_policy; ///< n00b_gc_stack_policy_t value.
    bool                  gc_isolated;    ///< true ⇒ this worker's C stack is EXCLUDED from the GC conservative scan (WP-002 `.isolation`); see @ref n00b_thread_spawn.
    _Atomic(bool)         gc_preempt_suspended; ///< WP-4 (D-040/D-041): set by the STW initiator when it PREEMPTIVELY suspended this RUNNING thread (vs. it self-parking at a checkin). When set, the GC scans @ref gc_captured_regs as conservative roots and uses @ref stack_top (= the captured SP) for the interrupted top frame. Cleared by `_n00b_restart_the_world` before `thread_resume`. _Atomic for cross-thread visibility; only the (single) STW initiator writes it, under the STW lock.
    uint64_t              gc_captured_regs[31]; ///< WP-4: GP registers (arm64 x0-x28, fp, lr) captured from the OS thread state at preemptive suspend, scanned CONSERVATIVELY (D-007/D-031: the interrupted frame's live pointers may be register-resident only). SP→@ref stack_top (stack bound, not a heap pointer); PC excluded (code). Written by the STW initiator under the STW lock, read by the GC in the same stop. Valid only while @ref gc_preempt_suspended.
    n00b_thread_record_t *record;       ///< Pointer into rt->threads[slot].

    /* Folded-in former thread_locals (D-005/D-012): each is now a
     * per-thread field reached via n00b_thread_self(), so a raw worker
     * thread needs zero TLS. */
    n00b_allocator_t     *current_allocator; ///< Scoped allocator override (was __n00b_current_allocator).
    n00b_string_t        *dl_last_error;     ///< Last dynamic-lib error (was dynamic_lib.c t_last_error).
    uint32_t              regex_nulls_last;  ///< Nulls cache scratch slot (was nulls.c `last`; NullsId-shaped).
    uint64_t              aba_ctr;           ///< Per-thread monotonic counter feeding _n00b_aba_tag() (lock-free-stack ABA tags). Per-thread (NOT per-CPU) to avoid the userspace thread-migration race that retired the per-processor STW plan (D-003); thread-local so the increment needs no atomic.

    /* Native (non-pthread) join state (WP-001 Phase 3, DF #4).  A raw OS
     * worker is created on its own n00b callstack (see `callstack`); when
     * it exits it publishes its return value into `join_result`, then
     * stores 1 into `join_futex` and wakes it (publish-then-wake).  The
     * joiner waits on `join_futex` (wait-then-recheck) and, once it reads
     * 1, reads `join_result` — and frees NOTHING (WP-3a Phase 2 / D-034:
     * the joiner observing join_futex == 1 is the worker's STILL-ON-STACK
     * window, so reclaiming the callstack/TCB here was a use-after-free).
     * The REAPER reclaims `callstack`/`tcb`/the slot at OS-CONFIRMED death
     * instead (see `reap_next` / `os_thread_port` / `child_tid_word`).  This
     * replaces pthread_join with a futex handshake; the worker itself NEVER
     * calls a libc errno-setting wrapper to do the wake (macOS: a Mach
     * thread has no TSD, so the wake goes through a direct syscall — see
     * thread.c). */
    struct n00b_callstack_t *callstack;  ///< Worker's OS callstack (nullptr for the main thread); reclaimed by the REAPER at OS-death (NOT the joiner), D-034.
    _Atomic(struct n00b_callstack_t *) altstack; ///< WP-3b (D-039): crash-handler alternate signal stack — a pool callstack region (so self() resolves on it via SA_ONSTACK, surviving a stack overflow), drawn by the spawner and returned to the pool by the REAPER at OS-death alongside @ref callstack. _Atomic because the crash handler reads it cross-thread when scanning slots (via rt->threads[i].thread->altstack). Lives on the PER-WORKER struct (not the shared slot record) so a slot reused before this worker is reaped cannot make the reaper return a live worker's altstack. nullptr until n00b_crash_install_altstack() runs.
    n00b_futex_t             join_futex; ///< 0 while running, 1 once the worker has exited.
    _Atomic(void *)          join_result;///< Worker's fn() return value, published before the join wake.

    /* 64-bit exit-code channel (WP-3a, D-032 Q2).  SEPARATE from
     * @ref join_result (the worker's `void *` fn-return): a worker may
     * stash an arbitrary 64-bit code via n00b_thread_exit() WITHOUT
     * affecting what its fn() returns.  Defaults to 0 (the struct is
     * zero-filled at allocation and n00b_thread_exit is STASH-ONLY, so a
     * worker that never calls it leaves this at 0 — spec "Thread
     * exiting": optional 64-bit code, default 0).  The launcher publishes
     * it alongside @ref join_result, BEFORE the join_futex
     * publish-then-wake, so a joiner that observes join_futex == 1 reads a
     * settled code.  Read via n00b_thread_exit_code(); MEANINGFUL ONLY
     * after a successful n00b_thread_join (the field is settled before the
     * wake, so the joiner that completed the handshake sees the final
     * value). */
    _Atomic(uint64_t)        exit_code;  ///< Worker's 64-bit exit code (default 0); see n00b_thread_exit / n00b_thread_exit_code.

    /* Spawn attributes (WP-002).  Set from the n00b_thread_spawn `_kargs`
     * carried spawner->launcher in the bundle, then copied onto this struct
     * by the launcher on the worker (where n00b_thread_self() resolves).  All three live
     * in the GC-visible, non-moving user_pool WITH the struct (WP-3a / D-034 —
     * GC-reclaimed when the struct becomes unreferenced, NOT bulk-freed at
     * teardown); `name` is the n00b_string_t the caller passed (its `data` is
     * also handed to the per-OS raw thread-name primitive). */
    n00b_string_t           *name;          ///< Caller-supplied OS thread name (nullptr = unnamed).
    n00b_finalizer_t         finalizer;     ///< Run once on worker exit, before the join wake (nullptr = none).
    void                    *finalizer_data;///< Opaque argument passed to @ref finalizer.

    /* Scheduling attributes (WP-002 Phase 3, D-025).  The REQUESTED tier and
     * the optional raw per-OS escape are recorded here by the launcher (on the
     * worker, after applying them to the OS primitive) so the request survives
     * for introspection even when the OS could not grant it (fail-soft). */
    n00b_thread_tier_t       sched_tier;    ///< Requested tier (N00B_THREAD_TIER_DEFAULT = none).
    bool                     sched_raw_set; ///< true when the raw escape was supplied (overrides @ref sched_tier).
    n00b_thread_sched_raw_t  sched_raw;     ///< Raw per-OS policy/priority (valid iff @ref sched_raw_set).

    /* Affinity attribute (WP-002 Phase 4, D-025).  The REQUESTED CPU-id set is
     * recorded here by the launcher (on the worker, after applying it to the OS
     * primitive) so the request survives for introspection even when the OS
     * could not honor it (a mask == 0 means none was requested).  Hard pin on
     * Linux/Win32, advisory on macOS — see @ref n00b_thread_cpuset_t. */
    n00b_thread_cpuset_t     affinity;      ///< Requested CPU affinity set (mask == 0 = none).

    /* Crash-handler SURFACE (WP-002 Phase 6, D-025 Q4).  The launcher copies
     * the registered handler (+ opaque data) onto this struct on the worker.
     * WP-002 ONLY STORES them — there is NO signal handler, NO sigaltstack, and
     * NO delivery path; crash delivery + the guard-page SIGSEGV handler that
     * will invoke this are WP-3.  Recorded here so WP-3's delivery path can find
     * the per-thread handler via the crashing worker's struct. */
    n00b_thread_crash_handler_t crash_handler;      ///< Registered crash callback (nullptr = none); INVOKED only in WP-3.
    void                       *crash_handler_data; ///< Opaque argument passed to @ref crash_handler (WP-3).

    /* Minimal n00b-owned per-thread TCB / platform-ABI TSD block (D-021).
     * A raw OS worker has a zero thread-pointer register, so the platform's
     * TSD-reading primitives (macOS os_unfair_lock reads `[TPIDRRO_EL0 +
     * 0x18]`, the __TSD_MACH_THREAD_SELF slot; glibc locks/errno read `%fs`)
     * fault the moment the worker runs real code.  The worker installs this
     * block as its thread pointer at entry (macOS: the `_thread_set_tsd_base`
     * machdep trap; Linux: CLONE_SETTLS).  It is NOT a libpthread `pthread_t`
     * and holds NO n00b per-thread data (identity is the stack ID word per
     * D-014/D-019; n00b state stays in this struct) — only the few
     * platform-ABI slots the OS's lock/errno paths index.  Mapped from a
     * non-GC region (a dedicated `n00b_mmap` page); freed by the REAPER at
     * OS-confirmed death (WP-3a Phase 2 / D-034 — alongside the callstack;
     * NOT the joiner, which frees nothing under D-034).
     * nullptr for the main thread and on Windows (the kernel-provided TEB
     * suffices). */
    void                    *tcb;       ///< Worker's platform TSD block (nullptr if none).

    /* OS-death-edge reclamation (WP-3a Phase 2, D-034).  Under D-034 a
     * worker's callstack + TCB + slot are reclaimed by the REAPER at
     * OS-CONFIRMED death — NOT by the joiner at the join_futex handshake
     * (the worker is still on its stack then).  The worker enqueues itself
     * on `rt->reap_pending` at the launcher exit, just before it goes off
     * its stack; the reaper drains the queue, checks the per-OS death edge,
     * and reclaims only confirmed-dead workers.  These fields carry the
     * per-OS liveness primitive + the queue link; they are meaningful only
     * for a spawned worker (zero for the main thread). */
    struct n00b_thread_t    *reap_next;    ///< Pending-reap queue link (rt->reap_pending).
    /**
     * @brief macOS: the worker's Mach thread port for the OS-death check.
     *
     * Seeded by the spawner from `thread_create` (the same port that goes
     * into TSD slot 3).  The worker self-terminates via
     * `bsdthread_terminate`; the death edge is this port becoming
     * unreachable, detected by the reaper with `thread_info(mach_port, …)`
     * returning a non-`KERN_SUCCESS` error (verified: a self-terminated
     * worker's control-port name turns into a dead name and `thread_info`
     * fails with `MACH_SEND_INVALID_DEST`).  The reaper deallocates the port
     * name after confirming death so it cannot be recycled under us.  0 on
     * non-macOS and for the main thread.
     */
    uint32_t                 os_thread_port;
    /**
     * @brief Linux: pointer to the CLONE_CHILD_CLEARTID child-tid word (death edge).
     *
     * clone()'s `ctid` argument is fixed at thread-create time, but the
     * permanent `n00b_thread_t` is allocated later by the worker itself
     * (`n00b_thread_init`), so the word the kernel clears cannot live inside
     * this struct.  It lives in the per-spawn bundle (stable, non-moving
     * system_pool, never relocated) and clone() is pointed at it; the launcher
     * records the word's address here so the reaper can read it via `self`.
     * At true thread exit the kernel writes 0 to that word and futex-wakes it
     * (the raw `CLONE_CHILD_CLEARTID` contract — no libc helper).  The spawner
     * seeds the word nonzero, so a 0 there is the unambiguous death edge.
     * nullptr on non-Linux and for the main thread.  Written-complete this WP;
     * Docker-verified later (D-026/D-028). */
    _Atomic(uint32_t)       *child_tid_word;
    /**
     * @brief Linux/Windows: the worker's OS thread id, for preemptive STW
     * suspension (WP-4 / D-040).  Linux: `gettid`, used as the `tgkill` target
     * for the suspend signal.  Windows: `GetCurrentThreadId`, used to
     * `OpenThread` + `SuspendThread`.  The launcher captures it on the worker
     * (where it resolves to the worker's own tid).  0 until set / on macOS
     * (which suspends via the Mach port, not a tid) / for the main thread (the
     * STW initiator, never itself suspended).  Written this WP; host-verified
     * later (D-026/D-028). */
    uint32_t                 os_tid;
};

/**
 * @brief Get a pointer to the calling thread's runtime-owned n00b_thread_t.
 *
 * Evaluates to the calling thread's `n00b_thread_t *`, or nullptr when
 * called before the runtime / main thread is registered.  O(1),
 * lock-free, TLS-free (D-004/D-014).
 *
 * This is a function-like **macro** (statement expression), not a
 * function, by design (D-019): ncc emits a GC stack-map push in every
 * framed function's prologue, and that push calls `n00b_thread_self()`.
 * A framed `n00b_thread_self()` would therefore recurse through its own prologue.
 * As a macro it has no prologue to instrument, and its entire body is
 * instrumentation-free — it expands to pure atomic loads (compiler
 * intrinsics via the `n00b_atomic_load` macro), `__builtin_frame_address`
 * for the SP, and masking arithmetic, calling no framed function.  In
 * particular it reaches the runtime through the `n00b_default_runtime`
 * global with the `n00b_option_*` macros rather than any accessor.
 *
 * Call sites are unchanged: `n00b_thread_self()` reads identically and
 * `&n00b_thread_self()->field` remains a valid address-of-a-field.
 *
 * Recovery (matching the Phase-1 geometry, D-014/D-015) — every branch is
 * O(1) and instrumentation-free:
 *   - Startup window (no runtime / no thread table): the bootstrap struct.
 *   - Main thread: an O(1) range check of the SP against the kernel-stack
 *     bounds published in N00B_MAIN_THREAD_SLOT's record at init.
 *   - Worker / non-main: O(1) masking (D-014).  A raw n00b worker (Phase 3)
 *     runs on an `S`-aligned, `S`-sized callstack, so the region base is
 *     `base = SP & ~(S-1)` and the slot id sits in the ID word at
 *     `base + S - 8` (the same geometry `n00b_callstack_id_word` computes).
 *     The recovered id indexes `rt->threads[id].thread`.  The result is
 *     VALIDATED before it is returned: the id must be in range and the
 *     recovered thread's published `stack_lo`/`stack_hi` must bracket the
 *     SP.  The validation is what keeps masking sound — a stale/garbage id
 *     (e.g. a slot read for a thread that has since exited) fails the
 *     bracket check and resolves to nullptr rather than returning a wrong
 *     thread, and a FOREIGN thread that happens to call n00b_thread_self() resolves to
 *     nullptr too (its masked id, if in range, will not bracket its SP).
 *     Inline, lock-free arithmetic — `n00b_callstack_id_word` is NOT called
 *     (it is framed; D-019 forbids a framed call on the n00b_thread_self() path); its
 *     masking is reproduced here.
 *
 *     KNOWN LIMITATION (flagged for the WP-close audit / VFS-excision WP):
 *     the validated masking READS the ID word at `base + S - 8` before it
 *     can validate.  For a genuine n00b worker that word is always in its
 *     own mapped usable region.  For a FOREIGN (non-callstack) thread — the
 *     VFS fuse/nfs frontend pthreads (out of project; thread.md scope), the
 *     only non-callstack threads left that can reach an n00b allocation and
 *     thus n00b_thread_self() — the masked base lands in that thread's own (non-aligned)
 *     stack mapping, so `base + S - 8` is usually mapped (in the same `S`
 *     window as the SP) but is not *guaranteed* mapped at the window top, so
 *     the read can in principle fault.  The four WP-001 thread tests never
 *     start a VFS frontend, so no foreign SP reaches this branch under test.
 *     The fully foreign-safe form requires excising those pthreads (their
 *     removal is already tracked, D-011/D-002); until then this is the
 *     mandated O(1) masking (D-014) with the validation above limiting the
 *     blast radius to the read itself.
 *
 * @note Each translation unit that uses this macro must have the full
 *       `n00b_runtime_t` definition (`core/runtime.h`) in scope, since
 *       the body dereferences `rt->threads[]` / `rt->max_threads`.  thread.h
 *       does NOT include core/runtime.h: runtime.h pulls in thread.h
 *       (n00b_thread_record_t is embedded by value in n00b_runtime_t's
 *       thread table), so including it here is a hard circular dependency.
 *       Callers therefore include core/runtime.h themselves (every current
 *       n00b_thread_self() caller already does, via the n00b internal-API umbrella).
 */
#define n00b_thread_self()                                                    \
    ({                                                                        \
        n00b_thread_t *_bl_result;                                            \
        if (!n00b_option_is_set(n00b_default_runtime)) {                      \
            _bl_result = &_n00b_bootstrap_thread;                             \
        }                                                                     \
        else {                                                                \
            n00b_runtime_t *_bl_rt = n00b_option_get(n00b_default_runtime);   \
            if (_bl_rt->threads == nullptr) {                                 \
                _bl_result = &_n00b_bootstrap_thread;                         \
            }                                                                 \
            else {                                                            \
                /* SP captured without adding a frame (D-019): never          \
                 * dereferenced, used only for range checks / masking. */     \
                void *_bl_sp = __builtin_frame_address(0);                    \
                n00b_thread_record_t *_bl_main                               \
                    = &_bl_rt->threads[N00B_MAIN_THREAD_SLOT];                \
                /* stack_lo is published last (release gate), so a non-null   \
                 * load implies stack_hi is visible too. */                   \
                void *_bl_lo = n00b_atomic_load(&_bl_main->stack_lo);         \
                void *_bl_hi = n00b_atomic_load(&_bl_main->stack_hi);         \
                if (_bl_lo == nullptr) {                                      \
                    /* Main-slot bounds unset: still single-threaded init. */ \
                    _bl_result = &_n00b_bootstrap_thread;                     \
                }                                                             \
                else if (_bl_sp >= _bl_lo && _bl_sp < _bl_hi) {               \
                    /* Main-thread O(1) range check (D-014). */               \
                    _bl_result = n00b_atomic_load(&_bl_main->thread);         \
                }                                                             \
                else {                                                        \
                    /* WORKER path — O(1) masking (D-014).  A raw n00b worker \
                     * runs on an S-aligned, S-sized callstack, so the region \
                     * base is SP & ~(S-1) and the slot id is in the ID word  \
                     * at base + S - 8 (the geometry n00b_callstack_id_word   \
                     * computes; reproduced inline here because that helper is \
                     * framed and D-019 forbids a framed call on this path).  \
                     * The recovered id indexes rt->threads[id], and the       \
                     * result is VALIDATED — id in range AND the recovered     \
                     * thread's published bounds bracket the SP — before it is \
                     * returned, so a stale/garbage id (or a foreign thread    \
                     * that reaches n00b_thread_self()) resolves to nullptr instead of a   \
                     * wrong thread.  See the flagged foreign-thread read note \
                     * in the @brief. */                                      \
                    _bl_result        = nullptr;                              \
                    void    *_bl_base = (void *)((uintptr_t)_bl_sp            \
                                                 & N00B_CALLSTACK_REGION_MASK);\
                    uint64_t *_bl_idw = (uint64_t *)((char *)_bl_base         \
                                                     + N00B_CALLSTACK_REGION_SIZE \
                                                     - N00B_CALLSTACK_ID_WORD_SIZE); \
                    uint64_t _bl_id = *_bl_idw;                               \
                    if (_bl_id < (uint64_t)_bl_rt->max_threads) {             \
                        n00b_thread_record_t *_bl_r                          \
                            = &_bl_rt->threads[_bl_id];                       \
                        void *_bl_rlo = n00b_atomic_load(&_bl_r->stack_lo);   \
                        void *_bl_rhi = n00b_atomic_load(&_bl_r->stack_hi);   \
                        if (_bl_rlo != nullptr && _bl_sp >= _bl_rlo          \
                            && _bl_sp < _bl_rhi) {                            \
                            _bl_result = n00b_atomic_load(&_bl_r->thread);    \
                        }                                                     \
                    }                                                         \
                }                                                             \
            }                                                                 \
        }                                                                     \
        _bl_result;                                                           \
    })

/**
 * @brief Record the current stack top for GC scanning.
 * @param thread Thread whose stack_top to update.
 * @pre @p thread is the calling thread's n00b_thread_t.
 * @post `thread->stack_top` points to the approximate top of the stack frame.
 */
static inline void
n00b_capture_stack_top(n00b_thread_t *thread)
{
    void *ptr;
#if defined(__GNUC__)
    // This dodges a silly warning.
    static volatile uint64_t x = ~0ULL;
    thread->stack_top          = (void *)(((uint64_t)&ptr) & x);
#else
    thread->stack_top = &ptr;
#endif
}

/**
 * @brief Get the unique (slot + generation) 64-bit thread ID.
 * @return The calling thread's `id_info.unique_id`, or 0 if unregistered.
 *
 * Out-of-line (defined in thread.c) rather than inline: it expands the
 * `n00b_thread_self()` macro, which dereferences the full
 * `n00b_runtime_t`, so it must be compiled where that type is complete —
 * not at every header that includes thread.h.  Unlike `n00b_thread_self()` itself
 * this helper is NOT on the GC stack-map push path, so being a framed
 * function is safe (no recursion; D-019 only requires `n00b_thread_self()` and its
 * on-path dependencies to be instrumentation-free).
 */
extern int64_t n00b_thread_unique_id(void);

/**
 * @brief Get the current thread's slot index.
 * @return The calling thread's slot id, or 0 if unregistered.
 *
 * Out-of-line for the same reason as n00b_thread_unique_id().
 */
extern int32_t n00b_thread_id(void);

/**
 * @brief Get the current thread's generation counter.
 * @return The calling thread's generation, or 0 if unregistered.
 *
 * Out-of-line for the same reason as n00b_thread_unique_id().
 */
extern int32_t n00b_thread_generation(void);

/**
 * @brief Spawn a new thread with full n00b lifecycle.
 *
 * Reserves a thread slot, allocates an n00b callstack, and creates a raw
 * OS thread (no pthread) wrapped in the n00b launcher (GC registration,
 * STW participation, lock cleanup on exit).
 *
 * DEFAULT-DETACHED MODEL (WP-3a, D-034/D-035).  A spawned worker needs NO
 * join to avoid a leak.  Its OS resources (the 8 MiB callstack and the
 * minimal TCB) are reclaimed by the runtime reaper at OS-CONFIRMED death
 * (the worker enqueues itself as it exits; the reaper returns the callstack
 * to the callstack pool and frees the TCB only once the OS confirms it is
 * off that stack — macOS dead Mach port / Linux CLONE_CHILD_CLEARTID), and
 * the returned n00b_thread_t struct is GC-owned (it lives in the runtime's
 * GC-visible, non-moving user_pool) and is collected once it becomes
 * unreferenced.  "Detached" is therefore the implicit model — there is no
 * `.detached`/`.attached` attribute (D-035): a thread is reaped and
 * collected regardless of whether anyone joins it.  "Joinable" simply means
 * the caller KEPT the returned handle: while that handle is held in a
 * GC-scanned location it keeps the struct alive, the caller may
 * n00b_thread_join() it for the result (see below), and the caller may
 * safely read the handle's fields after the worker has died.  Dropping the
 * last reference to a dead worker's handle lets the GC collect the struct.
 *
 * The positional `(fn, arg)` call shape is the common case and stays
 * source-compatible.  Optional spawn attributes are supplied as keyword
 * arguments (WP-002):
 *
 * @param fn   Thread entry point.
 * @param arg  Argument passed to @p fn.
 *
 * @kw name           OS thread name applied to the worker (per-OS raw
 *                    primitive) and stored on the worker's
 *                    n00b_thread_t::name.  nullptr (default) leaves the
 *                    worker unnamed.  Linux applies it via raw
 *                    prctl(PR_SET_NAME); Win32 via SetThreadDescription;
 *                    macOS stores it on the struct only (the off-libpthread
 *                    raw proc_info SETCONTROL path is a surfaced deferral —
 *                    its kernel-internal call number is unverifiable from any
 *                    SDK header, so it is not guessed on the worker path).
 * @kw finalizer      Cleanup callback run EXACTLY ONCE on the worker as it
 *                    exits, BEFORE the join handshake wakes the joiner
 *                    (so a joiner never observes "done" before cleanup).
 *                    nullptr (default) means no finalizer.  This is NOT a GC
 *                    struct finalizer: the n00b_thread_t is GC-owned (it lives
 *                    in the runtime's GC-visible user_pool and is collected
 *                    when unreferenced — WP-3a, D-034), so the finalizer runs
 *                    in the launcher exit path on the worker, not via the GC.
 * @kw finalizer_data Opaque argument passed to @p finalizer (default nullptr).
 * @kw custom_stack   Pointer to a caller-owned backing region (base + size)
 *                    for the worker's callstack (D-025).  When non-null, n00b
 *                    lays its `S`-aligned power-of-2 + ID-word geometry over
 *                    the caller's pages instead of allocating a fresh
 *                    callstack, so the worker still resolves `n00b_thread_self()` in O(1)
 *                    (`n00b_callstack_alloc_over`).  The region MUST be at
 *                    least `2 * N00B_CALLSTACK_REGION_SIZE` bytes (so an
 *                    `S`-aligned sub-region can be carved); an undersized /
 *                    un-alignable region fails the spawn with
 *                    `N00B_ERR_CALLSTACK_REGION_UNUSABLE`.  OWNERSHIP STAYS
 *                    WITH THE CALLER: n00b never frees or unmaps the region
 *                    (the reaper, which reclaims the callstack at OS-confirmed
 *                    death, only drops the mmap-tree registration for a
 *                    caller-owned region so the GC tree stays balanced — it
 *                    does not unmap the caller's pages); the caller must keep
 *                    the region alive until the worker has finished and free
 *                    it itself afterward.  The descriptor itself need only
 *                    live for the duration of the spawn call (it is copied).
 *                    The default (nullptr) allocates an n00b callstack as
 *                    usual.  This is also the mechanism that closes the Win32
 *                    `n00b_thread_self()` gap (D-023 W3): a Win32 worker run on the carved
 *                    n00b region resolves identity.  NOTE: `n00b_thread_spawn`
 *                    takes no `.allocator` kwarg, so the small `n00b_callstack_t`
 *                    bookkeeping struct is taken from the default allocator
 *                    regardless of the caller's arena context (the backing
 *                    pages themselves are the caller's own).
 * @kw priority       Requested scheduling tier (@ref n00b_thread_tier_t,
 *                    default N00B_THREAD_TIER_DEFAULT = leave OS default).
 *                    Applied to the worker on the worker itself via the per-OS
 *                    raw primitive (macOS Mach thread_policy_set; Linux raw
 *                    sched_setscheduler/setpriority; Win32 SetThreadPriority).
 *                    `.priority` and `.scheduler` are two names for the SAME
 *                    tier request (the normalized model folds policy+priority
 *                    into one ordered tier); when both are set the launcher
 *                    uses the higher.  An ungrantable privileged tier (e.g.
 *                    realtime without privilege) FAILS SOFT — the spawn still
 *                    succeeds and the requested tier is recorded on
 *                    n00b_thread_t::sched_tier.  See @ref n00b_thread_tier_t
 *                    for the full per-OS mapping table.
 * @kw scheduler      Alias for @kw priority (same tier request; see above).
 * @kw sched_raw      Optional pointer to a raw per-OS scheduling descriptor
 *                    (@ref n00b_thread_sched_raw_t).  When non-null it BYPASSES
 *                    the tier mapping and the launcher applies its {policy,
 *                    priority} directly to the OS primitive on the worker.
 *                    Also fails soft.  The descriptor is copied; it need only
 *                    live for the duration of the spawn call.  Default nullptr
 *                    (use the tier path).
 * @kw affinity       Optional pointer to a CPU-id set (@ref n00b_thread_cpuset_t)
 *                    applied to the worker on the worker itself.  HARD-PINS the
 *                    worker on Linux (raw sched_setaffinity) and Win32
 *                    (SetThreadAffinityMask); on macOS the apply is ADVISORY
 *                    ONLY (Mach thread_policy_set THREAD_AFFINITY_POLICY — a
 *                    scheduler hint, not a pin; tests must not assert a pin
 *                    there).  Fails soft: an un-honorable set leaves the worker
 *                    unpinned and the spawn still succeeds, with the REQUESTED
 *                    set recorded on n00b_thread_t::affinity.  An empty set
 *                    (mask == 0) or nullptr (default) requests no affinity.  The
 *                    descriptor is copied; it need only live for the duration of
 *                    the spawn call.  NUMA co-location is DEFERRED and expressed
 *                    meanwhile via this set — see @ref n00b_thread_cpuset_t.
 * @kw isolation      When true (default false), the worker runs ISOLATED from
 *                    the GC's conservative stack scan: the collector does NOT
 *                    treat the worker's raw C stack as a root source (it is
 *                    excluded from the conservative range scan in
 *                    n00b_scan_thread_stacks; the flag is recorded on
 *                    n00b_thread_t::gc_isolated and applied on the worker by
 *                    the launcher).  The worker's thread struct, its
 *                    n00b_thread_record_t, and its lock chains are STILL
 *                    scanned — isolation never corrupts the GC's view of the
 *                    worker's locks; only the worker's own C-stack words are
 *                    no longer scanned conservatively.
 *
 *                    SELF-REGISTRATION CONTRACT (caller responsibility): an
 *                    isolated worker MUST itself keep alive any GC-heap object
 *                    it holds, because the collector will no longer find that
 *                    object by scanning the worker's C stack.  It does so by
 *                    EITHER (a) being compiled with exact GC stack maps so its
 *                    live roots are published via the compiler's GC stack-frame
 *                    push (gc_stack_policy != N00B_GC_STACK_CONSERVATIVE — note
 *                    an exact-scanned worker is already not conservatively
 *                    scanned, so `.isolation` matters specifically for a
 *                    conservatively-scanned worker that wants OUT), OR (b)
 *                    registering the memory as a persistent GC root via
 *                    n00b_gc_register_root() / _n00b_gc_register_root() (see
 *                    include/core/gc.h), OR (c) keeping every such object also
 *                    reachable from an already-scanned root (the thread struct,
 *                    a registered global, or a non-isolated thread's stack).
 *                    A heap object that is reachable ONLY from an isolated
 *                    worker's C stack and is none of the above WILL be
 *                    collected as garbage → use-after-free.  WP-002 establishes
 *                    the EXCLUSION half (this flag) and documents this contract;
 *                    a dedicated per-thread "scan this extra region for me"
 *                    registration entry point beyond the existing
 *                    n00b_gc_register_root is NOT added here (it is not required
 *                    for the exclusion to be safe — (a)/(b)/(c) already cover
 *                    the contract — and is surfaced to the orchestrator as a
 *                    possible future convenience, not a WP-002 guess).
 *
 * @kw crash_handler  Optional per-thread crash callback
 *                    (@ref n00b_thread_crash_handler_t, default nullptr = none)
 *                    STORED on n00b_thread_t::crash_handler.  WP-002 is
 *                    SURFACE/STORAGE ONLY (D-025 Q4): the handler is recorded on
 *                    the worker's struct and NOTHING ELSE is done with it — no
 *                    signal handler is installed, no sigaltstack is set up, and
 *                    there is NO delivery path.  Crash DELIVERY and the
 *                    guard-page SIGSEGV handler that will INVOKE this callback
 *                    are DEFERRED TO WP-3; until then registering a handler is
 *                    inert beyond the storage.  The handler pointer fits in
 *                    sizeof(void *) and carries no libc type (D-002/D-009).
 * @kw crash_handler_data Opaque argument WP-3's delivery path will pass to
 *                    @kw crash_handler (default nullptr).  Stored on
 *                    n00b_thread_t::crash_handler_data; also inert in WP-002.
 *
 * @return     The spawned thread, or an error code (ENXIO, ENOMEM, the raw
 *             OS thread-creation failure code, or a negative
 *             `N00B_ERR_CALLSTACK_*` for an unusable `custom_stack` region).
 *
 * @pre  Runtime must be initialized.
 * @post The new thread participates in GC stop-the-world.
 */
extern n00b_result_t(n00b_thread_t *)
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
};

/**
 * @brief Wait for a spawned thread to finish and read its result (RESULT-ONLY).
 * @param thread  Thread to join (from n00b_thread_spawn). nullptr returns nullptr.
 * @return        Thread return value (the worker's `void *` fn-return).
 *
 * RESULT-ONLY (WP-3a, D-034).  This call WAITS for the worker to publish
 * "done", then returns the worker's `void *` fn-return.  It FREES NOTHING —
 * not the n00b_thread_t struct, not the worker's callstack, not its TCB.  It
 * is NEVER required to avoid a leak and is NEVER the cleanup path: the runtime
 * reaper reclaims the callstack/TCB at OS-CONFIRMED death (the worker is still
 * on its stack at the moment a joiner observes "done", so reclamation cannot
 * happen here), and the GC reclaims the struct once it becomes unreferenced
 * (the struct lives in the GC-visible user_pool).  Joining is therefore purely
 * a synchronization-plus-result operation; a worker that is never joined is
 * still reaped and collected (the default-detached model — see
 * @ref n00b_thread_spawn).
 *
 * The `void *` return is the worker's fn() return value and is INDEPENDENT
 * of the 64-bit exit code (D-032 Q2): a worker can both return a `void *`
 * and stash a separate exit code via n00b_thread_exit().  Read the exit
 * code with n00b_thread_exit_code() after this call returns; it remains
 * readable for as long as the handle is held (the worker settles the code
 * before the wake, and join frees nothing).
 */
extern void *n00b_thread_join(n00b_thread_t *thread);

/**
 * @brief Stash a 64-bit exit code for the calling worker (STASH-ONLY).
 * @param code  The 64-bit exit code to publish (default semantics: 0).
 *
 * Stores @p code into the calling worker's n00b_thread_t::exit_code and
 * RETURNS — it does NOT terminate the worker mid-function (D-033).  The
 * worker's fn() continues to run normally; the launcher publishes the
 * stashed code (the last value passed here, or 0 if never called) when the
 * worker exits, BEFORE the join handshake wakes the joiner.  Because the
 * exit code is a separate channel from the fn()-return, calling this does
 * NOT change the `void *` value n00b_thread_join() returns (D-032 Q2).
 *
 * If called more than once, the last value wins (each call overwrites the
 * stashed code).  Calling it from the main thread or a thread that is not
 * a spawned worker resolving via n00b_thread_self() is a no-op.
 *
 * @pre  The runtime is initialized and the caller resolves via
 *       n00b_thread_self() (a spawned worker on its n00b callstack).
 * @post n00b_thread_exit_code() on this thread, observed by a joiner after
 *       a successful join, yields @p code.
 */
extern void n00b_thread_exit(uint64_t code);

/**
 * @brief Read a thread's published 64-bit exit code.
 * @param thread  The thread whose exit code to read.
 * @return        The exit code @p thread stashed via n00b_thread_exit(),
 *                or 0 if it never called n00b_thread_exit().
 *
 * READ-VALIDITY CONTRACT: the returned value is meaningful only AFTER a
 * successful n00b_thread_join(thread).  The worker publishes its exit code
 * before the join_futex publish-then-wake, so a joiner that completed the
 * handshake reads the settled value; reading before the join is not
 * guaranteed to observe the final code.  The exit code is distinct from the
 * `void *` value returned by n00b_thread_join (D-032 Q2).
 *
 * Out-of-line (defined in thread.c) for parity with the other thread
 * accessors; it does not expand n00b_thread_self() (it reads @p thread
 * directly), so being a framed function is safe (D-019 only constrains the
 * n00b_thread_self() path).
 */
extern uint64_t n00b_thread_exit_code(n00b_thread_t *thread);

/**
 * @brief Check whether @p ptr is inside the calling thread's stack.
 *
 * This is stricter than checking the global mmap registry: some
 * platforms expose the main stack as multiple VM regions.  The
 * authoritative span is the registered n00b_mmap_stack region (the
 * OS-native main-stack bounds, or a worker's n00b callstack).
 */
extern bool n00b_current_thread_stack_contains(void *ptr);

#if defined __N00B_THREAD_INTERNAL
/**
 * @brief Initialize the calling thread's n00b_thread_t (internal).
 *
 * @kw runtime       Runtime to register with.
 * @kw acquired_slot Pre-acquired thread slot index (0 = auto-assign).
 * @kw callstack     The worker's OS callstack (nullptr for the main thread).
 *                   When set, the thread's stack bounds are taken directly
 *                   from the callstack region (a raw worker self-describes its
 *                   bounds; no OS stack query is needed) and recorded on the
 *                   thread so the n00b_thread_self() worker-masking back-check resolves.
 *
 * @pre Runtime must be initialized.
 * @post The calling thread is registered in the runtime's thread table
 *       and participates in STW pauses.
 */
void
n00b_thread_init() _kargs
{
    n00b_runtime_t *runtime            = n00b_get_runtime();
    uint32_t acquired_slot             = 0;
    struct n00b_callstack_t *callstack = nullptr;
};

/**
 * @brief Tear down the calling thread's n00b_thread_t.
 *
 * Releases any locks still held, clears the thread record, and
 * decrements `live_threads`.
 *
 * @pre  The calling thread was previously initialized via n00b_thread_init().
 * @post The thread slot is available for reuse.
 */
extern void n00b_thread_destroy(void);

/**
 * @brief Record the stack base address for a thread.
 * @param thread  Thread to update.
 * @param runtime Runtime owning the thread.
 */
extern void n00b_capture_stack_base(n00b_thread_t *thread, n00b_runtime_t *runtime);

/**
 * @brief Reaper backstop: reclaim OS-confirmed-dead workers (internal).
 *
 * Sweeps the runtime reap-pending queue (WP-3a Phase 2, D-034), returning the
 * callstack of every worker whose OS death edge has fired (macOS dead Mach port
 * / Linux CLONE_CHILD_CLEARTID futex) to the callstack pool, freeing its TCB,
 * and (macOS) deallocating its thread port; workers not yet confirmed dead stay
 * queued.  Bounded (one queue walk).  Called as a PROMPT backstop from the
 * conduit signal thread's poll loop so unheld detached workers are reaped
 * without waiting for the next spawn (the other reaper driver is the
 * callstack-pool slow path inside n00b_thread_spawn).  No dedicated reaper
 * thread.  A no-op when the runtime is not yet initialized.
 */
extern void n00b_thread_reap_pending(void);

#endif
