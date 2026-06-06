#pragma once

/**
 * @file eval.h
 * @brief Embedded-eval API: compile n00b expressions to JIT'd predicates.
 *
 * Wraps `n00b_cg_session_t` with the grammar (`grammars/n00b.bnf`)
 * pre-loaded, the FFI embed handler registered, and `lib/std/builtins.n`
 * imported. Consumers (naudit filters, future chalk/attest hooks)
 * call `n00b_eval_compile_predicate` with an expression source body
 * + an argument type name; the wrapper function is parsed, type-
 * checked, MIR-emitted, and JIT-compiled. The session is reusable —
 * each call gets a fresh wrapper-function name from a monotonic
 * counter so multiple predicates coexist.
 *
 * Consumers that need to register custom n00b types (e.g., the naudit
 * `match` type with extension methods) call
 * `n00b_eval_session_cg(s)` to obtain the underlying codegen
 * session, then perform their own
 * `n00b_type_register` / `n00b_type_add_method` /
 * `n00b_ffi_install_simple` calls before compiling predicates that
 * reference the registered type.
 *
 * No libc I/O — file reads go through `n00b_file_open(MMAP)` +
 * `n00b_file_as_buffer` per § 2.10/2.11.
 */

#include "n00b.h"
#include "adt/result.h"
#include "slay/codegen.h"

/**
 * @brief Opaque embedded-eval session handle.
 *
 * Holds a reference to the process-cached n00b grammar, the
 * underlying codegen session, the FFI embed registry, and the
 * monotonic predicate counter. Layout lives in `src/n00b/eval.c`.
 */
typedef struct n00b_eval_session n00b_eval_session_t;

/**
 * @brief Embedded n00b predicate function pointer.
 *
 * Takes ONE bound argument (the type registered with the session,
 * e.g., `n00b_naudit_match_t *` for naudit filters; raw integer for
 * the simple smoke cases). Returns bool.
 */
typedef bool (*n00b_eval_predicate_fn_t)(void *arg);

/**
 * @brief Error codes for the embedded-eval surface.
 *
 * Round-trip through `n00b_eval_err_str`.
 */
typedef enum {
    N00B_EVAL_ERR_NONE              =  0,  /**< Reserved (success path uses result_ok). */
    N00B_EVAL_ERR_GRAMMAR_OPEN      = -1,  /**< Cannot open `n00b.bnf` at `N00B_N00B_GRAMMAR_PATH`. */
    N00B_EVAL_ERR_GRAMMAR_PARSE     = -2,  /**< `n00b_bnf_load` failed on `n00b.bnf`. */
    N00B_EVAL_ERR_BUILTINS_OPEN     = -3,  /**< Cannot open `builtins.n` at `N00B_BUILTINS_PATH`. */
    N00B_EVAL_ERR_BUILTINS_LOAD     = -4,  /**< `builtins.n` failed to parse or codegen. */
    N00B_EVAL_ERR_BAD_ARGS          = -5,  /**< Null arg to session_new / compile_predicate. */
    N00B_EVAL_ERR_PARSE             = -6,  /**< Predicate wrapper failed to parse. */
    N00B_EVAL_ERR_ANNOT             = -7,  /**< Annotation walk failed on predicate. */
    N00B_EVAL_ERR_EMIT              = -8,  /**< MIR emission failed on predicate. */
    N00B_EVAL_ERR_JIT               = -9,  /**< JIT compile / function-name lookup failed. */
} n00b_eval_err_t;

/**
 * @brief Create an embedded-eval session.
 *
 * Lazily opens `grammars/n00b.bnf` (from `N00B_N00B_GRAMMAR_PATH`) via
 * `n00b_file_open(MMAP)` + `n00b_file_as_buffer`, then parses it
 * with `n00b_bnf_load` into a process-cached grammar reused by later
 * sessions. Creates an FFI embed registry via
 * `n00b_embed_registry_new` + `n00b_ffi_embed_register`. Opens a
 * codegen session with `.type_map = n00b_type_map` so built-in n00b
 * types resolve. Loads `lib/std/builtins.n` (from
 * `N00B_BUILTINS_PATH`) via `n00b_cg_session_run_module` so
 * stdlib symbols (`print`, etc.) are callable from predicate
 * expressions.
 *
 * @kw allocator  Allocator for the session struct. (default: nullptr)
 *
 * @return Ok(session) on success, Err carrying an
 *         `n00b_eval_err_t` on failure.
 */
extern n00b_result_t(n00b_eval_session_t *)
n00b_eval_session_new() _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Release a session's MIR context + associated state.
 *
 * Safe to call on null.
 */
extern void n00b_eval_session_free(n00b_eval_session_t *s);

/**
 * @brief Expose the underlying `n00b_cg_session_t *`.
 *
 * Consumers register additional FFI bindings or n00b types before
 * compiling predicates. The pointer lifetime is tied to @p s.
 */
extern n00b_cg_session_t *
n00b_eval_session_cg(n00b_eval_session_t *s);

/**
 * @brief Expose the loaded n00b grammar.
 *
 * Consumers parsing additional source text against the session's
 * grammar (e.g., for richer wrapper construction) call this.
 */
extern n00b_grammar_t *
n00b_eval_session_grammar(n00b_eval_session_t *s);

/**
 * @brief Compile an n00b expression into a JIT'd single-arg predicate.
 *
 * Wraps `expr_text` in the source
 *   `func _n00b_eval_p<N>(arg: <arg_type_name>) -> bool { return <expr_text> }`
 * where N is a per-session monotonic counter and `<arg_type_name>`
 * is the caller-supplied n00b type-spec for the bound argument
 * (e.g., `r"match"`, `r"int"`, `r"string"`). The wrapper is parsed
 * against the session's grammar, type-checked via
 * `n00b_compile_walk`, MIR-emitted, and JIT-compiled. The returned
 * function pointer dispatches the expression body against the bound
 * argument and returns bool.
 *
 * The caller is responsible for having registered any non-builtin
 * type referenced by `arg_type_name` (see `n00b_eval_session_cg`).
 *
 * @param s              Session.
 * @param expr_text      Expression body in n00b source. Must
 *                       reference the bound argument as `arg`.
 * @param arg_type_name  n00b type-spec string for `arg`.
 *
 * @kw allocator  Allocator for any per-call scratch. (default: nullptr)
 *
 * @return Ok(fn) carrying the JIT'd predicate, or Err carrying an
 *         `n00b_eval_err_t`.
 */
extern n00b_result_t(n00b_eval_predicate_fn_t)
n00b_eval_compile_predicate(n00b_eval_session_t *s,
                            n00b_string_t       *expr_text,
                            n00b_string_t       *arg_type_name) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Stable, human-readable string for an `n00b_eval_err_t`.
 *
 * Returns an r-string literal; callers may safely include it in
 * diagnostics or pass it to `n00b_string_eq`.
 */
extern n00b_string_t *n00b_eval_err_str(n00b_eval_err_t err);
