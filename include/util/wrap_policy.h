/**
 * @file wrap_policy.h
 * @brief Plain-C FFI shims + verdict core for EMBEDDED_N00B wrap policies
 *        (WP-017, D-052).
 *
 * The canonical wrap policy — the agent-guard — is a full n00b PROGRAM (see
 * `src/tools/n00b_wrap.c`) that decides allow/deny from process-ancestry FACTS
 * and, on allow, execs the wrapped target. It reaches those facts/effects
 * through per-symbol FFI shims installed into the wrap runtime
 * (`_n00b_obj_bundle_run_wrapped`). This header declares the two policy shims
 * defined in `src/util/wrap_policy.c` plus the pure ancestry-verdict core they
 * build on (exposed so it can be unit-tested with injected ancestry chains).
 *
 * The `cstring` parameter on @ref n00b_policy_eprint_shim makes this a § 11
 * plain-C ABI shim layer (libc-shaped FFI surface), like `src/util/exec_abi.c`.
 */

#pragma once

#include "core/string.h"
#include "adt/list.h"
#include "adt/array.h"
#include "util/proc.h"

/** @brief Default agent name set (comma-separated), used when
 *  `N00B_WRAP_AGENTS` is unset/empty. Plain C string (NOT an `r"..."` rstr):
 *  ncc recognizes rstr literals at lex time, so an rstr cannot come from a macro
 *  expansion — the consumer wraps this with `n00b_string_from_cstr`. */
#define N00B_WRAP_DEFAULT_AGENTS "claude"
/** @brief Default shell name set (comma-separated), used when
 *  `N00B_WRAP_SHELLS` is unset/empty. Plain C string (see
 *  @ref N00B_WRAP_DEFAULT_AGENTS for why this is not an rstr). */
#define N00B_WRAP_DEFAULT_SHELLS "sh,bash,zsh,dash,ksh,fish,tcsh,csh"

/**
 * @brief Pure agent-ancestry verdict over an explicit ancestry chain.
 *
 * Walks @p chain from index 1 (index 0 is the process itself): the first agent
 * ancestor reached through shells-only ancestors yields @c true (blocked); any
 * non-shell ancestor (or reaching the top) yields @c false (allowed). An agent
 * matches by kernel process name, executable basename, OR a path COMPONENT of
 * the executable (so a version-named launcher under a stable `.../claude/...`
 * directory still matches). Shells match by process/exe name only.
 *
 * @param chain  Ancestry list (child-to-ancestor), e.g. from
 *               @ref n00b_proc_ancestry; index 0 is the starting process.
 * @param agents Agent name set (each entry an `n00b_string_t *`).
 * @param shells Shell name set.
 * @return @c true to block, @c false to allow. A null/empty chain allows.
 */
extern bool
n00b_wrap_ancestry_is_blocked(n00b_list_t(n00b_proc_info_t *) *chain,
                              n00b_array_t(n00b_string_t *)    *agents,
                              n00b_array_t(n00b_string_t *)    *shells);

/**
 * @brief FFI FACT shim: is the calling process a blocked agent?
 *
 * Reads the real process ancestry (@ref n00b_proc_ancestry) and the
 * `N00B_WRAP_AGENTS` / `N00B_WRAP_SHELLS` environment sets (defaults above),
 * then applies @ref n00b_wrap_ancestry_is_blocked. Fail-open: returns 0 (allow)
 * when ancestry cannot be determined.
 *
 * @return 1 if the caller is a blocked agent, else 0. Installed as an FFI target
 *         (`i64` return, no params) for embedded n00b policy programs.
 */
extern int64_t n00b_caller_is_blocked_agent(void);

/**
 * @brief FFI EFFECT shim: write @p msg to standard error.
 *
 * The plain-C ABI (`cstring`) form a policy program calls to emit a human-facing
 * message (e.g. the agent refusal) on stderr — the n00b language `print` builtin
 * targets stdout only.
 *
 * @param msg Message text (a `cstring` FFI argument); a null @p msg prints
 *            nothing.
 * @return 0 always (installed with an `i64` return for a uniform FFI ABI).
 */
extern int64_t n00b_policy_eprint_shim(const char *msg);
