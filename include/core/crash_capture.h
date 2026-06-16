/**
 * @file crash_capture.h
 * @brief Generalized, structured crash-log / backtrace capability for libn00b.
 *
 * This is the structured, two-phase generalization of the diagnostic-only
 * fault handler in core/crash.c.  Where crash.c WRITES a one-line breadcrumb to
 * an fd (async-signal-safe, allocation-free), this module RETURNS a structured
 * @ref n00b_crash_capture_t object that a caller can inspect, store, render, or
 * ship off-box.
 *
 * MARSHALABILITY (design goal, NOT yet fully achieved): the schema is built for
 * it -- every address is a uintptr_t VALUE (never a live, followed pointer), the
 * register file is flat, and dest_arena is an opaque value -- and bare strings
 * marshal cleanly.  But n00b_marshal() on a whole capture currently fails
 * (status=5, "static pointer is not a registered static object") inside the
 * per-frame struct, which embeds n00b_option_t(...) generic fields.  Completing
 * marshalability is a documented follow-up: convert n00b_crash_frame_t's
 * (and n00b_crash_meminfo_t's) embedded n00b_option_t fields to plain
 * `value + bool present` pairs (the style n00b_crash_meminfo_t already uses),
 * which removes the embedded _generic_struct that marshal mishandles.  See
 * TODO(crash-marshal).
 *
 * Two-phase model (see the design spec, "n00b-crash-backtrace-api"):
 *
 *  - Phase A (capture): async-signal-safe.  Runs inline in a signal handler or
 *    synchronously for a manual capture.  Collects registers, the ordered raw
 *    instruction-pointer list (frame-pointer walk), and per-frame module /
 *    offset / slide (via the AS-safe @ref n00b_mmap_handler_lookup) plus, when
 *    safe, per-frame GC/alloc info.  Builds everything in a throw-away,
 *    per-thread SCRATCH arena that grows via registry-free n00b_mmap
 *    (.skip_register=true), then COPIES the finished, exactly-sized,
 *    pointer-free-value result into a caller-chosen DESTINATION arena.
 *
 *  - Phase B (resolve): NOT signal-safe.  Enriches a capture in place with
 *    symbol names + source file:line out of signal context.
 *
 * Allocation contract: copy-out into the GC heap is REFUSED while the world is
 * stopped (or otherwise GC-unsafe for writing the heap).  There is no defer
 * path: the caller must supply an explicit non-GC'd @c .dest, or the capture
 * fails with @ref N00B_CRASH_ERR_NEED_NONGC_DEST.  Copy-out into a non-moving /
 * GC-hidden destination (the signal-path default) is always allowed.
 *
 * Safety-critical invariants:
 *  1. Per-thread recursion guard: a fault DURING capture returns a minimal,
 *     degraded result (`reentered = true`), never infinite recursion.
 *  2. Addresses are @c uintptr_t VALUES, never live, dereferenceable heap
 *     pointers, so the capture survives GC churn and is marshalable.
 */
#pragma once

#include "n00b.h"
#include "adt/option.h"
#include "adt/result.h"
#include "adt/list.h"

// ---------------------------------------------------------------------------
// Tuning constants (soft knobs; see design Appendix A).
// ---------------------------------------------------------------------------

#define N00B_CRASH_DEFAULT_MAX_FRAMES      128
#define N00B_CRASH_DEFAULT_SCRATCH_KB      16
#define N00B_CRASH_MAX_REENTRY             1
#define N00B_CRASH_EST_STR_BYTES_PER_FRAME 96

// Size of the flat raw-GPR file (see n00b_crash_regs_t.gpr).  arm64 needs 31
// (x0..x30); x86_64 needs 16 (rax..r15); 31 covers both.
#define N00B_CRASH_GPR_MAX                 31

// ---------------------------------------------------------------------------
// Schema (all value-typed / pointer-free at the address boundary so the
// capture is self-contained and marshalable -- see the design spec section 3).
// ---------------------------------------------------------------------------

typedef enum n00b_crash_arch_t : uint8_t {
    N00B_CRASH_ARCH_UNKNOWN = 0,
    N00B_CRASH_ARCH_ARM64,
    N00B_CRASH_ARCH_X86_64,
} n00b_crash_arch_t;

typedef struct n00b_crash_regs_t {
    n00b_crash_arch_t arch;
    bool              valid; // false => ucontext null / unsupported arch
    uintptr_t         pc;    // program counter / rip
    uintptr_t         sp;    // stack pointer / rsp
    uintptr_t         fp;    // frame pointer / rbp / x29
    uintptr_t         lr;    // link register (arm64); 0 on x86_64
    // Full GPR file captured verbatim from ucontext.  Stored FLAT (not a union
    // of by-value structs) so the enclosing type keeps a precise GC pointer map
    // and stays marshalable -- ncc cannot statically describe a union whose
    // members are by-value aggregates.  Interpretation is arch-specific:
    //   arm64:  gpr[0..30] = x0..x30 (x29=fp, x30=lr); gpr_aux = pstate (cpsr)
    //   x86_64: gpr[0..15] = rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,r8..r15;
    //           gpr_aux = rflags
    // pc/sp/fp/lr are hoisted above; consumers needing only those ignore gpr.
    // Unused slots are zero.
    uintptr_t gpr[N00B_CRASH_GPR_MAX];
    uint64_t  gpr_aux;
} n00b_crash_regs_t;

typedef enum n00b_crash_mem_class_t : uint8_t {
    N00B_CRASH_MEM_UNKNOWN = 0,   // find_alloc_info miss / not run
    N00B_CRASH_MEM_HEAP_OOB,      // n00b_alloc_oob
    N00B_CRASH_MEM_HEAP_INLINE,   // n00b_alloc_inline
    N00B_CRASH_MEM_STATIC_OBJECT, // n00b_alloc_static_range
} n00b_crash_mem_class_t;

typedef struct n00b_crash_meminfo_t {
    // Named `mem_class` rather than the spec's `class`: ncc's parser rejects
    // `class` as a struct field name (reserved-word handling).  The schema
    // intent is unchanged.
    n00b_crash_mem_class_t mem_class;
    bool                   resolved; // false => not attempted or miss
    uint64_t               type_hash; // 0 if unknown ('typehash' is reserved in ncc)
    n00b_option_t(n00b_string_t *) type_name;
    uint32_t               alloc_len; // 0 if unknown
    bool                   is_array;
    bool                   no_scan;
} n00b_crash_meminfo_t;

// TODO(crash-marshal): the embedded n00b_option_t(...) fields below are what
// blocks whole-capture marshalling (see the file header).  Converting them to
// plain `value + bool present` pairs (as n00b_crash_meminfo_t already does)
// is the planned fix; deferred as a public-schema change pending sign-off.
typedef struct n00b_crash_frame_t {
    uint32_t  index;        // 0 = innermost (the faulting frame)
    uintptr_t pc;           // raw instruction pointer (return addr for callers)
    bool      pc_is_return; // true => subtract 1 for symbolication

    // ---- Phase A (AS-safe), via n00b_mmap_handler_lookup ----
    n00b_option_t(n00b_string_t *) module;        // image/library path
    n00b_option_t(uintptr_t)       module_offset; // pc - load_base
    n00b_option_t(uintptr_t)       load_slide;     // ASLR slide of the module
    uintptr_t                      module_start;   // 0 if module unresolved
    uintptr_t                      module_end;

    // ---- Phase A, per-frame GC/alloc info (best-effort) ----
    n00b_crash_meminfo_t meminfo;

    // ---- Phase B (NOT signal-safe), symbolication ----
    n00b_option_t(n00b_string_t *) symbol;
    n00b_option_t(uintptr_t)       symbol_offset; // pc - symbol_start
    n00b_option_t(n00b_string_t *) source_file;
    n00b_option_t(uint32_t)        source_line;
    n00b_option_t(uint32_t)        source_col;
    bool                           inlined;
} n00b_crash_frame_t;

typedef enum n00b_crash_cause_t : uint8_t {
    N00B_CRASH_CAUSE_NONE = 0, // explicit/manual capture, no fault
    N00B_CRASH_CAUSE_SEGV,
    N00B_CRASH_CAUSE_BUS,
    N00B_CRASH_CAUSE_STACK_OVERFLOW,
    N00B_CRASH_CAUSE_PANIC,
    N00B_CRASH_CAUSE_OTHER,
} n00b_crash_cause_t;

// Error codes carried on the err side of the capture result.  A capture only
// errs when even a degraded result cannot be returned in the requested
// destination.
typedef enum n00b_crash_err_t : uint8_t {
    N00B_CRASH_ERR_NONE = 0,
    N00B_CRASH_ERR_NOT_INITIALIZED, // the n00b runtime is not yet initialized
    N00B_CRASH_ERR_NEED_NONGC_DEST, // GC-heap dest requested in a GC-unsafe
                                    // context with no explicit non-GC .dest
} n00b_crash_err_t;

// Human-readable string for a crash error code (see n00b_crash_err_t).
extern const char *
n00b_crash_err_str(n00b_crash_err_t err);

typedef struct n00b_crash_capture_t {
    n00b_crash_cause_t cause;
    int                signal_number;      // 0 for non-signal captures
    uintptr_t          fault_address;      // si_addr; 0 if N/A
    bool               on_alternate_stack; // captured from the altstack?

    uint32_t           thread_id;
    uint32_t           thread_generation;
    uint64_t           os_tid;

    n00b_crash_regs_t  regs;

    // Frames, innermost-first.
    n00b_list_t(n00b_crash_frame_t *) *frames;

    // Fidelity / truncation flags.
    bool     frames_truncated; // hit the frame cap OR a corrupt-stack stop
    bool     reentered;        // produced by the recursion guard (degraded)
    bool     phase_b_done;     // symbolication has run
    uint32_t frames_requested; // configured cap
    uint32_t frames_captured;  // actual

    // Destination allocator this capture was copied into, as an OPAQUE address
    // value (uintptr_t, not a followed pointer) so the object stays marshalable
    // per the schema's address-as-value rule.  Meaningful only in the capturing
    // process; cast back to n00b_allocator_t* there (e.g. n00b_crash_resolve).
    uintptr_t dest_arena;
} n00b_crash_capture_t;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * @brief Arm the per-thread crash scratch infrastructure.  Idempotent.
 *
 * Called once, late in n00b_init, alongside n00b_crash_init.  Establishes the
 * default non-moving, GC-hidden destination allocator for the signal path.
 * Scratch is throw-away and grows on demand via registry-free n00b_mmap, so it
 * needs no per-thread pre-reservation here.
 */
extern void
n00b_crash_pool_init(void) _kargs
{
    uint32_t max_frames = N00B_CRASH_DEFAULT_MAX_FRAMES;
    uint32_t scratch_kb = N00B_CRASH_DEFAULT_SCRATCH_KB;
};

/**
 * @brief Capture a structured backtrace (Phase A).
 *
 * @kw uctx         Opaque ucontext_t* (nullptr => manual capture; live regs).
 * @kw siginfo      Opaque siginfo_t* (nullptr for manual capture).
 * @kw signal_num   Delivered signal (0 for manual capture).
 * @kw dest         Destination arena the finished capture is copied INTO.
 *                  nullptr => the default non-moving, GC-hidden crash allocator.
 *                  If dest is the GC heap (or nullptr resolving to it) AND the
 *                  context is GC-unsafe for copy-out (STW), the call returns
 *                  N00B_CRASH_ERR_NEED_NONGC_DEST unless an explicit non-GC
 *                  .dest was supplied.
 * @kw max_frames   Frame cap (0 => configured default).
 * @kw with_meminfo Run per-frame n00b_find_alloc_info in Phase A.  Auto-
 *                  downgraded to false when the world is stopped.
 * @kw from_signal  true => stay strictly AS-safe.
 */
extern n00b_result_t(n00b_crash_capture_t *)
n00b_crash_capture(void) _kargs
{
    void             *uctx         = nullptr;
    void             *siginfo      = nullptr;
    int               signal_num   = 0;
    n00b_allocator_t *dest         = nullptr;
    uint32_t          max_frames   = 0;
    bool              with_meminfo = true;
    bool              from_signal  = false;
};

/**
 * @brief Manual "give me my backtrace now".
 *
 * Wraps n00b_crash_capture with from_signal=false and live register read.
 * Defaults the destination to the GC heap (healthy path => an ordinary,
 * marshalable n00b object).
 *
 * @kw dest       Destination arena (nullptr => GC heap).
 * @kw max_frames Frame cap (0 => configured default).
 * @kw resolve    Run Phase B immediately (default true).
 */
extern n00b_result_t(n00b_crash_capture_t *)
n00b_backtrace_here(void) _kargs
{
    n00b_allocator_t *dest       = nullptr;
    uint32_t          max_frames = 0;
    bool              resolve    = true;
};

/**
 * @brief Enrich a capture with symbol names + source file:line (Phase B).
 *
 * MUST NOT be called from signal context.  Idempotent.  Best effort: frames
 * that cannot be symbolicated keep their option-none symbol/source fields.
 * Returns true if at least one frame gained symbol or source info.
 *
 * @kw allocator Allocator for resolved strings (nullptr => capture->dest_arena).
 * @kw demangle  Demangle symbol names (default true).
 */
extern bool
n00b_crash_resolve(n00b_crash_capture_t *capture) _kargs
{
    n00b_allocator_t *allocator = nullptr;
    bool              demangle  = true;
};

/**
 * @brief Render a (possibly partially-resolved) capture to an n00b_string_t.
 *
 * Pure consumer; safe out of signal context only.  Honors option-none fields.
 *
 * @kw allocator Allocator for the rendered string (nullptr => GC heap).
 */
extern n00b_string_t *
n00b_crash_render(n00b_crash_capture_t *capture) _kargs
{
    bool              include_registers  = true;
    bool              include_meminfo    = true;
    bool              one_line_per_frame = true;
    n00b_allocator_t *allocator          = nullptr;
};

/**
 * @brief AS-safe last-resort renderer: writes a capture to a raw fd using only
 *        raw write syscalls.  No allocation.  Safe in signal context.
 */
extern void
n00b_crash_render_raw_fd(n00b_crash_capture_t *capture, int fd);
