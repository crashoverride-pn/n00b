/**
 * @file proc.h
 * @brief Process utilities — liveness of an arbitrary PID.
 *
 * A thin libn00b platform wrapper so callers can check whether a process
 * exists without doing the syscall directly (mirrors the @ref n00b_path_get_mode
 * wrapper around stat(2)). Distinct from @c n00b_subproc, which manages child
 * processes this runtime spawned.
 */

#pragma once

#include "core/alloc.h"

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
