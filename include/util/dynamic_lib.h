/**
 * @file util/dynamic_lib.h
 * @brief n00b-idiomatic wrapper over the POSIX dynamic linker.
 *
 * Replaces ad-hoc `<dlfcn.h>` use throughout libn00b consumers (most
 * importantly libn00b_aws's demangle-generated headers — see
 * [[project_n00b_aws_via_rust_shim]] in the SKP auto-memory). The
 * implementation in `src/util/dynamic_lib.c` is the single POSIX
 * boundary file; nothing else in n00b touches `dlopen` / `dlsym` /
 * `dlclose` directly.
 *
 * Two surfaces are exposed:
 *
 *   - n00b-typed (`n00b_dynamic_lib_open`, `n00b_dynamic_lib_symbol`,
 *     `n00b_dynamic_lib_close`) — for hand-written n00b code. Takes
 *     `n00b_string_t *` for paths and symbol names; returns
 *     `n00b_result_t(T)` so callers get either the value or an
 *     `n00b_dynamic_lib_err_t`.
 *
 *   - C-string boundary (`n00b_dynamic_lib_open_cstr` /
 *     `_symbol_cstr` / `_close`) — drop-in for code that already
 *     speaks the `dlopen` / `dlsym` / `dlclose` shape; in particular
 *     this is what `~/slop/bin/demangle` emits into its generated
 *     headers when invoked with `--loader-prefix=n00b_dynamic_lib`.
 *
 * Handles are opaque (`n00b_dynamic_lib_t`) and live in the n00b GC
 * heap with a finalizer that closes the underlying `dlopen` handle if
 * the caller never explicitly closes it. This means a loaded shared
 * library is unloaded when the last reference becomes unreachable —
 * the cstr boundary returns a raw `void *` for `dlopen`-shape
 * compatibility, but the pointee is the same managed structure.
 */
#pragma once

#include "n00b.h"
#include "core/string.h"
#include "adt/result.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct n00b_dynamic_lib_t n00b_dynamic_lib_t;

typedef enum {
    N00B_DYNLIB_OK              = 0,
    N00B_DYNLIB_ERR_INVALID_ARG = -1,
    N00B_DYNLIB_ERR_NOT_FOUND   = -2,
    N00B_DYNLIB_ERR_LOAD_FAILED = -3,
    N00B_DYNLIB_ERR_NO_SYMBOL   = -4,
    N00B_DYNLIB_ERR_PLATFORM    = -5,
} n00b_dynamic_lib_err_t;

/** @brief Static debug string for an `n00b_dynamic_lib_err_t` code. */
extern const char *n00b_dynamic_lib_err_str(n00b_dynamic_lib_err_t err);

/**
 * @brief Open the shared library at @p path.
 *
 * All symbols are resolved up-front (`RTLD_NOW`) and confined to the
 * caller's namespace (`RTLD_LOCAL`) so loading two shims that happen
 * to share a symbol name doesn't collide in the global namespace.
 *
 * @return  `ok` carrying the handle on success; `err` carrying an
 *          `n00b_dynamic_lib_err_t` otherwise. The full diagnostic
 *          string from the dynamic linker is available via
 *          `n00b_dynamic_lib_last_error()` on the same thread.
 */
extern n00b_result_t(n00b_dynamic_lib_t *)
n00b_dynamic_lib_open(n00b_string_t *path);

/**
 * @brief Resolve @p name in @p lib.
 *
 * @return  `ok` with the function/data pointer; `err` with
 *          `N00B_DYNLIB_ERR_NO_SYMBOL` if the symbol is absent.
 */
extern n00b_result_t(void *)
n00b_dynamic_lib_symbol(n00b_dynamic_lib_t *lib, n00b_string_t *name);

/**
 * @brief Release @p lib explicitly.
 *
 * Optional — the GC finalizer closes the underlying handle when the
 * struct becomes unreachable. Call this when you want deterministic
 * unload (e.g. plugin reload).
 */
extern void n00b_dynamic_lib_close(n00b_dynamic_lib_t *lib);

/**
 * @brief Thread-local diagnostic from the most recent failed call.
 *
 * Empty string if no failure has been recorded on this thread.
 */
extern n00b_string_t *n00b_dynamic_lib_last_error(void);

/* ------------------------------------------------------------------
 * C-string boundary — drop-in for code expecting dlopen/dlsym/dlclose
 * shapes. Used by `~/slop/bin/demangle` output when invoked with
 * `--loader-prefix=n00b_dynamic_lib`. Returns and accepts
 * `void *` exactly like the POSIX surface; the underlying pointee
 * is still an `n00b_dynamic_lib_t` allocated on the n00b GC heap.
 * ------------------------------------------------------------------ */

extern void *n00b_dynamic_lib_open_cstr(const char *path);
extern void *n00b_dynamic_lib_symbol_cstr(void *lib, const char *name);
extern void  n00b_dynamic_lib_close_cstr(void *lib);
extern void *n00b_dynamic_lib_current_symbol_cstr(const char *name);
extern const char *n00b_dynamic_lib_addr_symbol_cstr(void *addr);

#ifdef __cplusplus
}
#endif
