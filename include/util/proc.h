/**
 * @file proc.h
 * @brief Process utilities — liveness, and cross-platform introspection
 *        (pid, parent pid, and ancestry).
 *
 * libn00b's subprocess API (@ref n00b_subproc_t) spawns and manages CHILD
 * processes. This module is the complementary primitive: it inspects an
 * arbitrary process — whether it is still alive, the current process, or the
 * chain of ANCESTORS up to the top reachable parent.
 *
 * The public surface is a single, platform-neutral API. The OS-specific
 * mechanism (macOS `libproc` vs Linux `/proc`, `kill(pid, 0)` for liveness) is
 * confined to the implementation, so callers write one code path on every
 * platform.
 */

#pragma once

#include "core/alloc.h"
#include "core/string.h"
#include "adt/list.h"
#include "adt/result.h"

/**
 * @brief Test whether a process with the given PID currently exists.
 *
 * @param pid Process id to test.
 *
 * @return @c true if a process with @p pid exists and is visible to this
 *         process. On POSIX this is @c kill(pid, 0) succeeding, or failing with
 *         @c EPERM (the process exists but is owned by another user).
 *         @c false if @p pid <= 0, if no such process exists (@c ESRCH), or on
 *         platforms without support.
 */
extern bool n00b_proc_is_alive(int64_t pid);

/**
 * @brief Identity snapshot of a single process.
 *
 * All three name fields are nullable: a process whose executable path or name
 * cannot be resolved (permissions, exited, kernel thread) still yields its
 * `pid` and `ppid`, so an ancestry walk can continue past it.
 *
 * proc_name is the kernel-reported process name (macOS proc_bsdinfo,
 * Linux /proc/<pid>/comm) or the executable basename on Windows. It may differ
 * from the executable's on-disk filename or be truncated by the OS (Linux caps
 * it at 15 bytes).
 */
typedef struct {
    int64_t        pid;       /**< The process id. */
    int64_t        ppid;      /**< Parent pid; 0 when none/unknown. */
    n00b_string_t *exe_path;  /**< Full executable path, or nullptr if unresolvable. */
    n00b_string_t *exe_name;  /**< Basename of @ref exe_path, or nullptr. */
    n00b_string_t *proc_name; /**< Kernel process name (comm), or nullptr. */
} n00b_proc_info_t;

/* Domain error codes. Negative to avoid collision with errno. */
#define N00B_PROC_ERR_NO_SUCH_PID   (-1) /**< The pid is invalid or not queryable. */
#define N00B_PROC_ERR_LOOKUP_FAILED (-2) /**< The OS query failed. */
#define N00B_PROC_ERR_UNSUPPORTED   (-3) /**< No implementation for this platform. */

/**
 * @brief Human-readable description of an `N00B_PROC_ERR_*` code.
 * @param code An `N00B_PROC_ERR_*` value (or 0).
 * @return A static description string (never nullptr).
 */
extern n00b_string_t *n00b_proc_err_str(n00b_err_t code);

/**
 * @brief The current process id.
 * @return The calling process's pid.
 */
extern int64_t n00b_proc_self_pid(void);

/**
 * @brief The local machine's hostname (cross-platform).
 *
 * Kernel-reported node name: POSIX `gethostname`, Windows
 * `GetComputerNameEx(ComputerNameDnsHostname)`. Returns the empty string on
 * failure. Worker-thread safe — a thin syscall wrapper that touches no
 * locale/TLS state (unlike libc string/locale converters). The result is
 * freshly allocated on the current heap.
 */
extern n00b_string_t *n00b_get_hostname(void);

/**
 * @brief Look up identity info for a process by pid.
 * @param pid The process id.
 * @kw allocator Optional allocator (defaults to the runtime allocator).
 * @return Ok(info) with `pid`/`ppid` populated — `exe_path`/`exe_name` may be
 *         nullptr if the path is unresolvable. Err(N00B_PROC_ERR_*) when the
 *         pid cannot be queried at all.
 * @pre `pid > 0` (a non-positive pid returns Err(N00B_PROC_ERR_NO_SUCH_PID);
 *      this is an advisory precondition, body-guarded rather than trapping).
 * @post `!result.is_ok || (result.ok != nullptr && result.ok->pid == pid)`.
 */
extern n00b_result_t(n00b_proc_info_t *)
n00b_proc_get_info(int64_t pid) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Build the ancestry chain starting at @p pid and climbing to parents.
 *
 * Index 0 is the starting process (when @p include_self is true); each later
 * element is the parent of the previous one (child-to-ancestor order). The walk
 * stops at pid 0/1, the first parent that cannot be queried, or after
 * @p max_depth entries (cycle guard).
 *
 * @param pid Starting pid; if `<= 0`, the current process is used.
 * @kw allocator    Optional allocator (defaults to the runtime allocator).
 * @kw max_depth    Maximum number of entries to collect (default 64; clamped to
 *                  at least 1).
 * @kw include_self If true (default), index 0 is the starting process; if
 *                  false, the list begins at its parent.
 * @return Ok(list) of `n00b_proc_info_t *` in child-to-ancestor order, or
 *         Err(N00B_PROC_ERR_*) when even the first process cannot be queried.
 * @post `!result.is_ok || result.ok != nullptr`.
 */
extern n00b_result_t(n00b_list_t(n00b_proc_info_t *) *)
n00b_proc_ancestry(int64_t pid) _kargs {
    n00b_allocator_t *allocator    = nullptr;
    int64_t           max_depth    = 64;
    bool              include_self = true;
};
