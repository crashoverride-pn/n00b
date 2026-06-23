#pragma once

/**
 * @file debug.h
 * @brief Debugger substrate: software-settable breakpoints and hardware
 *        watchpoints.
 *
 * This library lets a program set breakpoints and hardware data watchpoints
 * on itself at runtime. When a trap fires it either invokes a caller-supplied
 * callback (which can inspect/modify CPU state and decide how to resume) or it
 * raises a debugger trap so an attached debugger catches it. It is intended as
 * the foundation a real in-process debugger is built on; the trap-to-debugger
 * path is the interim story until that debugger exists.
 *
 * ## Two trap sources
 *
 * - **Hardware watchpoints** (`n00b_debug_watch`): the CPU debug registers fire
 *   when a watched address is written (or read). No code modification; there
 *   are only a handful of hardware slots (typically 4), shared with hardware
 *   breakpoints.
 * - **Breakpoints** (`n00b_debug_break`): either a *hardware* execute
 *   breakpoint (a debug-register slot, no code modification — the default) or a
 *   *software* breakpoint (a trap instruction written into the code, unlimited
 *   in number but requiring writable code).
 *
 * ## Callback vs. trap
 *
 * Every install takes an optional `on_hit` callback. If you supply one, it runs
 * when the trap fires and returns an action (continue / disable / escalate to a
 * debugger trap). If you leave `on_hit` as `nullptr`, the hit is delivered as a
 * debugger trap directly.
 *
 * ## Signal-context safety
 *
 * Hit callbacks run in async exception context (a Mach exception server thread
 * on macOS, a signal handler on Linux). Treat them like signal handlers: do not
 * allocate from the GC heap, take GC locks, or call into the broader n00b
 * runtime. Read/modify the `n00b_debug_hit_t`, decide an action, and return.
 *
 * ## Platform support
 *
 * - **macOS / arm64**: hardware watchpoints and hardware breakpoints via the
 *   Mach exception server and the ARM64 debug registers.
 * - **Linux / x86-64 and arm64**: hardware watchpoints/breakpoints via the
 *   debug registers and a SIGTRAP handler; software breakpoints via trap
 *   instructions.
 *
 * Unsupported combinations return @ref N00B_DEBUG_ERR_UNSUPPORTED rather than
 * failing silently.
 */

#include <n00b.h>
#include "adt/result.h"

/* =========================================================================
 * Errors
 * ========================================================================= */

/**
 * @brief Error codes returned by the debug API.
 *
 * Codes are negative so they never collide with `errno`. Functions that return
 * a value return `n00b_result_t(T)` carrying one of these on failure; functions
 * with no value return the code directly. Use @ref n00b_debug_err_str for a
 * human-readable description.
 */
typedef enum {
    /** Operation succeeded. */
    N00B_DEBUG_OK = 0,

    /** All hardware debug slots are in use (watchpoints and hardware
     *  breakpoints share the same small pool). */
    N00B_DEBUG_ERR_NO_SLOT = -1,

    /** A nullptr or otherwise invalid argument was supplied. */
    N00B_DEBUG_ERR_INVALID_ARGUMENT = -2,

    /** Failed to install the exception/signal backend (signal handler on
     *  Linux, Mach exception port/thread on macOS). */
    N00B_DEBUG_ERR_SIGNAL_HANDLER = -3,

    /** A software breakpoint could not be written because the code page is
     *  not writable. */
    N00B_DEBUG_ERR_MEMORY_PROTECTION = -4,

    /** This architecture/platform cannot perform the requested operation. */
    N00B_DEBUG_ERR_UNSUPPORTED = -5,

    /** Internal error (library bug). */
    N00B_DEBUG_ERR_INTERNAL = -6,

    /** A bounded wait (e.g. n00b_debug_wait_for_debugger) timed out. */
    N00B_DEBUG_ERR_TIMEOUT = -7,
} n00b_debug_err_t;

/**
 * @brief Human-readable description of a debug error code.
 *
 * @param e A @ref n00b_debug_err_t value.
 * @return A static rich string describing @p e (never free it).
 */
extern n00b_string_t *n00b_debug_err_str(n00b_debug_err_t e);

/* =========================================================================
 * Hit context — CPU state at a trap (callback-only, transient)
 * ========================================================================= */

/**
 * @brief Opaque CPU state captured at a breakpoint or watchpoint hit.
 *
 * Passed to an @ref n00b_debug_hit_fn callback. Valid only for the duration of
 * that callback; do not retain it. Register reads/writes apply to the thread
 * that took the trap and take effect when the callback returns.
 */
typedef struct n00b_debug_hit_t n00b_debug_hit_t;

/**
 * @brief Program counter at the point of the trap.
 * @param hit The hit context.
 * @return The faulting instruction pointer (PC/RIP).
 */
extern void *n00b_debug_hit_pc(n00b_debug_hit_t *hit);

/**
 * @brief Stack pointer at the point of the trap.
 * @param hit The hit context.
 * @return The stack pointer (SP/RSP).
 */
extern void *n00b_debug_hit_sp(n00b_debug_hit_t *hit);

/**
 * @brief The address that triggered the trap.
 * @param hit The hit context.
 * @return For a watchpoint, the watched data address; for a breakpoint, the
 *         breakpoint's code address.
 */
extern void *n00b_debug_hit_addr(n00b_debug_hit_t *hit);

/**
 * @brief Read a general-purpose register.
 *
 * @param hit The hit context.
 * @param reg Register index in the platform's ABI/DWARF GPR numbering
 *            (x0..x30 on arm64; the System V DWARF order on x86-64). PC and SP
 *            have dedicated accessors above.
 * @return The register's 64-bit value, or 0 if @p reg is out of range.
 */
extern uint64_t n00b_debug_hit_reg(n00b_debug_hit_t *hit, int32_t reg);

/**
 * @brief Overwrite a general-purpose register.
 *
 * The new value is written back to the trapped thread when the callback
 * returns @ref N00B_DEBUG_CONTINUE.
 *
 * @param hit The hit context.
 * @param reg Register index (see @ref n00b_debug_hit_reg).
 * @param val The value to set.
 */
extern void n00b_debug_hit_set_reg(n00b_debug_hit_t *hit, int32_t reg, uint64_t val);

/**
 * @brief (Watchpoint only) The word at the watched address before the write.
 *
 * Best-effort: meaningful when the watched region is a single pointer-sized
 * word. Undefined for breakpoints.
 *
 * @param hit The hit context.
 * @return The prior value at the watched address.
 */
extern void *n00b_debug_hit_old_value(n00b_debug_hit_t *hit);

/**
 * @brief (Watchpoint only) The value the faulting store is writing.
 *
 * Best-effort: recovered by decoding the faulting store instruction. Returns
 * `nullptr` when the store could not be decoded, for read watchpoints, or for
 * breakpoints.
 *
 * @param hit The hit context.
 * @return The value being written, or `nullptr` if unavailable.
 */
extern void *n00b_debug_hit_new_value(n00b_debug_hit_t *hit);

/**
 * @brief Action a hit callback returns to control resumption.
 */
typedef enum {
    /** Resume the program (with any register edits applied). */
    N00B_DEBUG_CONTINUE,

    /** Clear this trap, then resume — a one-shot breakpoint/watchpoint. The
     *  handle becomes inactive (still valid to pass to `*_clear`). */
    N00B_DEBUG_DISABLE,

    /** Escalate: deliver a debugger trap (default-disposition SIGTRAP / Mach
     *  EXC_BREAKPOINT) so an attached debugger catches it. */
    N00B_DEBUG_TRAP,
} n00b_debug_action_t;

/**
 * @brief Callback invoked when a breakpoint or watchpoint fires.
 *
 * Runs in async exception context — see the signal-safety note in the file
 * overview.
 *
 * @param hit       Transient CPU state for this hit.
 * @param user_data The `user_data` supplied at install time.
 * @return The resumption action.
 */
typedef n00b_debug_action_t (*n00b_debug_hit_fn)(n00b_debug_hit_t *hit, void *user_data);

/* =========================================================================
 * Hardware watchpoints
 * ========================================================================= */

/** @brief Access pattern that triggers a watchpoint. */
typedef enum {
    /** Trigger on writes only. */
    N00B_DEBUG_WATCH_WRITE = 1,
    /** Trigger on reads or writes. */
    N00B_DEBUG_WATCH_RW = 3,
} n00b_debug_watch_kind_t;

/**
 * @brief Watched span, in bytes.
 *
 * The hardware requires the span to be a power of two and the watched address
 * to be naturally aligned for it. The numeric value of each constant is the
 * byte count.
 */
typedef enum {
    N00B_DEBUG_WATCH_SIZE_1 = 1,
    N00B_DEBUG_WATCH_SIZE_2 = 2,
    N00B_DEBUG_WATCH_SIZE_4 = 4,
    N00B_DEBUG_WATCH_SIZE_8 = 8,
} n00b_debug_watch_size_t;

/**
 * @brief Opaque handle to an installed watchpoint.
 *
 * Lives in non-GC, signal-reachable memory. Valid until @ref
 * n00b_debug_watch_clear.
 */
// Defined here (not opaque) because ncc must see a registered typeid + body to
// use the type in n00b_result_t / n00b_array_t. Treat the fields as internal:
// read state through the accessors below, not directly.
typedef struct {
    void                   *addr;
    n00b_debug_watch_size_t size;
    n00b_debug_watch_kind_t kind;
    n00b_debug_hit_fn       on_hit;
    void                   *user_data;
    int32_t                 slot;    // hardware debug-register slot, -1 if none
    bool                    enabled;
} n00b_debug_watchpoint_t;

/**
 * @brief Set a hardware watchpoint on a data address.
 *
 * @param addr The address to watch. Must be naturally aligned for the span.
 * @kw size      Watched span (default: @ref N00B_DEBUG_WATCH_SIZE_8).
 * @kw kind      Access pattern (default: @ref N00B_DEBUG_WATCH_WRITE).
 * @kw on_hit    Callback to run on a hit; `nullptr` (default) delivers a
 *               debugger trap instead.
 * @kw user_data Opaque value passed to @p on_hit (default: `nullptr`).
 * @kw allocator Allocator for the handle (default: `nullptr` → the runtime
 *               system pool). The handle is reached from async exception
 *               context, so it must be non-GC and non-moving; pass only a
 *               signal-safe allocator (or leave the default).
 *
 * @return On success, the watchpoint handle. On failure, an error code:
 *         @ref N00B_DEBUG_ERR_NO_SLOT if all hardware slots are in use,
 *         @ref N00B_DEBUG_ERR_INVALID_ARGUMENT for a bad address/size,
 *         @ref N00B_DEBUG_ERR_SIGNAL_HANDLER if the backend won't install,
 *         @ref N00B_DEBUG_ERR_UNSUPPORTED on an unsupported target.
 */
extern n00b_result_t(n00b_debug_watchpoint_t *)
n00b_debug_watch(void *addr) _kargs
{
    n00b_debug_watch_size_t size      = N00B_DEBUG_WATCH_SIZE_8;
    n00b_debug_watch_kind_t kind      = N00B_DEBUG_WATCH_WRITE;
    n00b_debug_hit_fn       on_hit    = nullptr;
    void                   *user_data = nullptr;
    n00b_allocator_t       *allocator = nullptr;
};

/**
 * @brief Remove a watchpoint and free its hardware slot.
 * @param wp The watchpoint handle (invalid after this call).
 * @return @ref N00B_DEBUG_OK, or an error code.
 */
extern n00b_debug_err_t n00b_debug_watch_clear(n00b_debug_watchpoint_t *wp);

/**
 * @brief Re-arm a previously disabled watchpoint.
 * @param wp The watchpoint handle.
 * @return @ref N00B_DEBUG_OK, or an error code.
 */
extern n00b_debug_err_t n00b_debug_watch_enable(n00b_debug_watchpoint_t *wp);

/**
 * @brief Temporarily disarm a watchpoint without releasing its slot.
 * @param wp The watchpoint handle.
 * @return @ref N00B_DEBUG_OK, or an error code.
 */
extern n00b_debug_err_t n00b_debug_watch_disable(n00b_debug_watchpoint_t *wp);

/** @brief The watched address. @param wp Handle. @return The address. */
extern void *n00b_debug_watch_addr(n00b_debug_watchpoint_t *wp);
/** @brief The watched span. @param wp Handle. @return The size. */
extern n00b_debug_watch_size_t n00b_debug_watch_size(n00b_debug_watchpoint_t *wp);
/** @brief The access pattern. @param wp Handle. @return The kind. */
extern n00b_debug_watch_kind_t n00b_debug_watch_kind(n00b_debug_watchpoint_t *wp);
/** @brief Whether the watchpoint is currently armed. @param wp Handle. */
extern bool n00b_debug_watch_is_enabled(n00b_debug_watchpoint_t *wp);

/* =========================================================================
 * Breakpoints
 * ========================================================================= */

/** @brief Breakpoint implementation strategy. */
typedef enum {
    /** Hardware execute breakpoint via a debug-register slot. No code
     *  modification; shares the hardware slot pool with watchpoints. */
    N00B_DEBUG_BREAK_HW = 0,
    /** Software breakpoint: a trap instruction written into the code.
     *  Unlimited in count, but requires the target code page to be writable. */
    N00B_DEBUG_BREAK_SW = 1,
} n00b_debug_break_kind_t;

/**
 * @brief Opaque handle to an installed breakpoint.
 *
 * Lives in non-GC, signal-reachable memory. Valid until @ref
 * n00b_debug_break_clear.
 */
// Defined here (not opaque) for the same typeid reason as the watchpoint
// handle. Treat the fields as internal; use the accessors below.
typedef struct {
    void                   *addr;
    n00b_debug_break_kind_t kind;
    n00b_debug_hit_fn       on_hit;
    void                   *user_data;
    int32_t                 slot;    // hardware slot (HW kind), -1 for software
    bool                    enabled;
} n00b_debug_breakpoint_t;

/**
 * @brief Set a breakpoint at a code address.
 *
 * @param addr The instruction address to break on.
 * @kw kind      Implementation strategy (default: @ref N00B_DEBUG_BREAK_HW).
 * @kw on_hit    Callback to run on a hit; `nullptr` (default) delivers a
 *               debugger trap instead.
 * @kw user_data Opaque value passed to @p on_hit (default: `nullptr`).
 * @kw allocator Allocator for the handle (default: `nullptr` → the runtime
 *               system pool). The handle is reached from async exception
 *               context, so it must be non-GC and non-moving; pass only a
 *               signal-safe allocator (or leave the default).
 *
 * @return On success, the breakpoint handle. On failure, an error code:
 *         @ref N00B_DEBUG_ERR_NO_SLOT (hardware, slots exhausted),
 *         @ref N00B_DEBUG_ERR_MEMORY_PROTECTION (software, code not writable),
 *         @ref N00B_DEBUG_ERR_INVALID_ARGUMENT,
 *         @ref N00B_DEBUG_ERR_SIGNAL_HANDLER,
 *         @ref N00B_DEBUG_ERR_UNSUPPORTED.
 */
extern n00b_result_t(n00b_debug_breakpoint_t *)
    n00b_debug_break(void *addr) _kargs {
        n00b_debug_break_kind_t kind      = N00B_DEBUG_BREAK_HW;
        n00b_debug_hit_fn       on_hit    = nullptr;
        void                   *user_data = nullptr;
        n00b_allocator_t       *allocator = nullptr;
    };

/**
 * @brief Remove a breakpoint, restoring the original code (software) or
 *        releasing the slot (hardware).
 * @param bp The breakpoint handle (invalid after this call).
 * @return @ref N00B_DEBUG_OK, or an error code.
 */
extern n00b_debug_err_t n00b_debug_break_clear(n00b_debug_breakpoint_t *bp);

/**
 * @brief Re-arm a previously disabled breakpoint.
 * @param bp The breakpoint handle.
 * @return @ref N00B_DEBUG_OK, or an error code.
 */
extern n00b_debug_err_t n00b_debug_break_enable(n00b_debug_breakpoint_t *bp);

/**
 * @brief Temporarily disarm a breakpoint without removing it.
 * @param bp The breakpoint handle.
 * @return @ref N00B_DEBUG_OK, or an error code.
 */
extern n00b_debug_err_t n00b_debug_break_disable(n00b_debug_breakpoint_t *bp);

/** @brief The breakpoint address. @param bp Handle. @return The address. */
extern void *n00b_debug_break_addr(n00b_debug_breakpoint_t *bp);
/** @brief The implementation strategy. @param bp Handle. @return The kind. */
extern n00b_debug_break_kind_t n00b_debug_break_kind(n00b_debug_breakpoint_t *bp);
/** @brief Whether the breakpoint is currently armed. @param bp Handle. */
extern bool n00b_debug_break_is_enabled(n00b_debug_breakpoint_t *bp);

/* =========================================================================
 * Enumeration
 * =========================================================================
 *
 * Walk the currently-installed traps. The callback runs in normal (non-signal)
 * context; return `true` to keep going, `false` to stop early. Reading each
 * handle via the accessors above is fine; do NOT install or clear traps from
 * inside the callback. (A callback form is used rather than a returned
 * container because the handles are non-GC and the registry is walked under a
 * lock — see docs/debug.md.)
 */

/** @brief Per-watchpoint iteration callback. @return false to stop early. */
typedef bool (*n00b_debug_watch_iter_fn)(n00b_debug_watchpoint_t *wp, void *user_data);
/** @brief Per-breakpoint iteration callback. @return false to stop early. */
typedef bool (*n00b_debug_break_iter_fn)(n00b_debug_breakpoint_t *bp, void *user_data);

/**
 * @brief Invoke @p fn for each installed watchpoint.
 * @param fn        Callback; iteration stops early if it returns false.
 * @param user_data Opaque value passed to @p fn.
 */
extern void n00b_debug_watch_foreach(n00b_debug_watch_iter_fn fn, void *user_data);

/**
 * @brief Invoke @p fn for each installed breakpoint.
 * @param fn        Callback; iteration stops early if it returns false.
 * @param user_data Opaque value passed to @p fn.
 */
extern void n00b_debug_break_foreach(n00b_debug_break_iter_fn fn, void *user_data);

/* =========================================================================
 * Debugger trap / attach helpers
 * ========================================================================= */

/**
 * @brief Raise a debugger trap at the call site.
 *
 * Executes the architecture's trap instruction (BRK / INT3). If a debugger is
 * attached it stops here; if not, the trap takes its default disposition.
 */
extern void n00b_debug_trap(void);

/**
 * @brief Report whether a debugger is currently attached to this process.
 * @return `true` if a debugger/tracer is attached, `false` otherwise.
 */
extern bool n00b_debug_is_attached(void);

/**
 * @brief Block until a debugger attaches.
 *
 * @kw timeout_ms Milliseconds to wait, or a negative value (default: -1) to
 *                wait indefinitely.
 * @return @ref N00B_DEBUG_OK once a debugger is attached, or an error code if
 *         the wait times out or the platform cannot report attach state.
 */
extern n00b_debug_err_t n00b_debug_wait_for_debugger() _kargs {
    int32_t timeout_ms = -1;
};
