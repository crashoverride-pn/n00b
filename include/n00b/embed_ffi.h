#pragma once

/**
 * @file embed_ffi.h
 * @brief FFI embed literal handler.
 *
 * Registers the `'ffi` embed handler, which parses FFI binding
 * declarations and returns an `n00b_ffi_module_t` object.  Calling
 * `install()` on the object generates MIR wrapper functions that
 * bridge between n00b calling conventions and C ABI.
 *
 * ## Example (inside a comptime block)
 *
 * ```n00b
 * comptime {
 *     ffi_mod = [=[
 *         strlen : (string -> cstr) -> i64 = strlen
 *         write  : (i32, buffer -> (ptr, len)) -> i64 = write
 *     ]=]'ffi
 *
 *     ffi_mod.install()
 * }
 * ```
 *
 * Each binding line declares:
 * - n00b-side name and signature
 * - Per-parameter conversion (n00b type -> C type)
 * - C symbol to link against
 * - Optional: keyword args, ownership, error mapping
 */

#include "n00b/embed.h"

/**
 * @brief Opaque FFI module object returned by the `'ffi` embed handler.
 *
 * Holds parsed binding declarations.  Call `install()` (via the
 * extension method) to emit MIR wrapper functions into the active
 * codegen session.
 */
typedef struct n00b_ffi_module_t {
    void    *bindings;      /**< Internal ffi_binding_t array. */
    int32_t  binding_count; /**< Number of bindings. */
    void    *session;       /**< `n00b_cg_session_t *` that created this. */
    bool     installed;     /**< True after install() has been called. */
} n00b_ffi_module_t;

/**
 * @brief Get the BNF grammar text for the FFI mini-language.
 * @return Static string containing the FFI BNF.
 */
extern n00b_string_t *n00b_ffi_bnf(void);

/**
 * @brief Register the `'ffi` embed handler on a registry.
 * @param registry  Embed handler registry.
 */
extern void n00b_ffi_embed_register(n00b_dict_untyped_t *registry);

/**
 * @brief Install all FFI bindings from a module, emitting MIR wrappers.
 * @param self  The FFI module object.
 */
extern void n00b_ffi_module_install(n00b_ffi_module_t *self);

/**
 * @brief Install one simple C symbol binding directly into a codegen session.
 *
 * This supports the legacy `extern name(types) -> type {}` syntax.  The
 * n00b-side wrapper name and C symbol name are the same unless `c_name` is
 * provided.  Supported parameter spellings include direct integer/pointer
 * types and `cstring`, which accepts a n00b `string` and passes a C string.
 */
extern bool n00b_ffi_install_simple(n00b_cg_session_t *session,
                                    const char        *n00b_name,
                                    const char        *c_name,
                                    const char       **param_types,
                                    int32_t            param_count,
                                    const char        *ret_type);

/**
 * @brief Make a C function address available to name-based FFI installs.
 *
 * `n00b_ffi_install_simple()` and `'ffi` bindings normally resolve C names
 * through the platform dynamic-symbol API. Some platforms, notably Windows,
 * do not expose executable-local symbols to that API unless the executable
 * exports them. This registration path keeps the public FFI contract
 * name-based while allowing embedders and tests to provide exact addresses.
 */
extern bool n00b_ffi_register_symbol(const char *name, void *addr);

/**
 * @brief Register the `n00b_ffi_module_t` type and its `install` method.
 *
 * Called during startup (after type registry init) so that comptime
 * method dispatch can find the `install` extension method.
 */
extern void n00b_ffi_module_type_register(void);
