/**
 * @file exec.h
 * @brief Process-image replacement primitive (`exec`) — the n00b-level wrapper
 *        over the POSIX `exec*` family.
 *
 * libn00b's subprocess API (@ref n00b_subproc_t) and the object-bundle exec
 * runtime spawn and wait on CHILD processes. This module is the complementary
 * primitive: it REPLACES the current process image with another executable, the
 * way a shell's `exec` builtin does. On success it never returns; control passes
 * to the new program. It returns only when the replacement fails.
 *
 * @ref n00b_exec is the n00b-typed surface (n00b strings + arrays). @ref
 * n00b_exec_shim is its plain-C ABI form: simple scalar/pointer parameters with
 * no `_kargs`/`n00b_result_t` struct ABI, so it can be installed as an FFI
 * target callable from embedded n00b policy programs (it converts and forwards
 * to @ref n00b_exec, so the single image-replacement boundary stays in one
 * place).
 *
 * § 2.10: image replacement has no pre-existing n00b wrapper — this module IS
 * that wrapper. Its `execvp`/`execve` calls are the only raw OS-boundary surface
 * here, confined to @ref n00b_exec, mirroring the justified raw `execv` in the
 * object-bundle exec-replace path (`src/compiler/objfile/obj_bundle_exec_run.c`)
 * and the raw process calls in `src/util/proc.c`.
 */

#pragma once

#include "core/alloc.h"
#include "core/string.h"
#include "adt/array.h"
#include "adt/result.h"

/* Domain error codes. Negative to avoid collision with errno. */
#define N00B_EXEC_ERR_NULL_CMD      (-1) /**< @p cmd was null. */
#define N00B_EXEC_ERR_LAUNCH_FAILED (-2) /**< The `exec*` call returned (failed). */

/**
 * @brief Human-readable description of an `N00B_EXEC_ERR_*` code.
 * @param code An `N00B_EXEC_ERR_*` value (or 0).
 * @return A static description string (never nullptr).
 */
extern n00b_string_t *n00b_exec_err_str(n00b_err_t code);

/**
 * @brief Replace the current process image with @p cmd.
 *
 * On success this function DOES NOT RETURN — the calling image is replaced by
 * @p cmd and execution continues there. It returns only on failure.
 *
 * When @p env is null the new program inherits the current environment and
 * @p cmd is resolved with `PATH` semantics (`execvp`); when @p env is supplied
 * @p cmd is taken as a literal path with the given environment (`execve`).
 *
 * @param cmd Executable path (or `PATH`-resolvable name when @p env is null).
 *
 * @kw argv      Argument vector (each element an `n00b_string_t *`). When null or
 *               empty, `{ cmd }` is used as the single argument. (default: null)
 * @kw env       Environment vector (`"NAME=value"` strings). When null, the
 *               current environment is inherited. (default: null)
 * @kw allocator Allocator for the transient pre-exec scratch vectors (§4.1).
 *               (default: nullptr)
 *
 * @pre @p cmd is non-null. A null @p cmd is an advisory precondition,
 *      body-guarded as `Err(N00B_EXEC_ERR_NULL_CMD)` rather than trapping
 *      (D-031).
 * @post Returns ONLY on failure (success replaces the process image and never
 *       returns). The `bool` result payload is a PLACEHOLDER: the `Ok(true)`
 *       branch is UNREACHABLE BY DESIGN — on success `exec*` never returns, so no
 *       Ok value is ever produced. Callers treat any return as failure and
 *       inspect the `Err` code. The bool exists only to give `n00b_result_t` a
 *       concrete success type. The implementation `ensures` the always-failure
 *       invariant (`!result.is_ok || result.ok == false`), matching the
 *       `n00b_obj_bundle_exec_run` exec-replace precedent.
 */
extern n00b_result_t(bool)
n00b_exec(n00b_string_t *cmd) _kargs {
    n00b_array_t(n00b_string_t *) *argv      = nullptr;
    n00b_array_t(n00b_string_t *) *env       = nullptr;
    n00b_allocator_t              *allocator = nullptr;
};

/**
 * @brief Plain-C ABI shim over @ref n00b_exec for FFI installation.
 *
 * Converts the raw C arguments to n00b values and forwards to @ref n00b_exec, so
 * the single `exec*` image-replacement boundary remains in @ref n00b_exec. Like
 * @ref n00b_exec it does not return on success.
 *
 * @param cmd  Executable path / `PATH`-resolvable name (inherits the current
 *             environment; the shim does not pass a custom env).
 * @param argv Null-terminated C argument vector, or null for `{ cmd }`.
 *
 * @return Only on failure: a nonzero `N00B_EXEC_ERR_*` code (never returns on
 *         success).
 */
extern int64_t n00b_exec_shim(const char *cmd, const char *const *argv);
