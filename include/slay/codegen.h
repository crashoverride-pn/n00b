#pragma once

/**
 * @file codegen.h
 * @brief Code generation API with MIR backend — session/module architecture.
 *
 * Provides a language-agnostic code generation layer that:
 * - Maintains a **persistent MIR context** across module compilations
 * - Supports **incremental compilation** (one MIR module per source/REPL expr)
 * - Auto-infers semantics for common patterns (binary `+` -> add, etc.)
 * - Lets languages register per-NT callbacks for custom constructs
 * - Provides pre-flight audit of codegen coverage
 * - Supports interpret, JIT, and compiled output via MIR
 *
 * ## Architecture
 *
 * ```
 * n00b_cg_session_t (persistent, one per process/REPL)
 *   +-- mir_ctx           single MIR_context_t
 *   +-- import_table      FFI imports (auto-registered or manual)
 *   +-- global_scope      merged public symbols from all modules
 *   +-- modules[]         compilation order
 *   +-- handlers/op_map   shared codegen callbacks
 *
 * n00b_cg_module_t (one per file or REPL expression)
 *   +-- mir_module        MIR_module_t
 *   +-- module_scope      this module's symbols
 *   +-- per-module emit state (labels, loops, temps)
 * ```
 *
 * ## Naming
 *
 * - `n00b_cg_session_*` — session lifecycle, module management
 * - `n00b_cg_module_*` — module lifecycle, symbol queries
 * - `n00b_cg_*` — builder API (functions, locals, instructions)
 */

#include "slay/cf_label.h"
#include "slay/grammar.h"
#include "slay/diagnostic.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmacro-redefined"
#include "mir.h"
#include "mir-gen.h"
#pragma clang diagnostic pop

// ============================================================================
// Forward declarations
// ============================================================================

typedef struct n00b_cg_session_t n00b_cg_session_t;
typedef struct n00b_cg_module_t  n00b_cg_module_t;
typedef struct n00b_sym_entry_t  n00b_sym_entry_t;

/**
 * @brief Backward compatibility: `n00b_codegen_t` is now `n00b_cg_session_t`.
 *
 * All existing builder functions (`n00b_cg_begin_func`, `n00b_cg_emit_*`, etc.)
 * continue to accept `n00b_codegen_t *` (which is `n00b_cg_session_t *`).
 * They operate on the session's active module.
 */
typedef n00b_cg_session_t n00b_codegen_t;

// ============================================================================
// Machine-level type categories
// ============================================================================

/**
 * @brief Machine-level type tags for codegen values.
 *
 * Numeric types map 1:1 to MIR types. Pointer-like tags (STRING
 * through PTR) currently use MIR_T_I64 at the MIR level on 64-bit
 * targets and carry semantic information so the codegen can dispatch
 * operators and builtins correctly.
 *
 * Languages provide a `type_map` callback to translate their type
 * system into these tags.
 */
typedef enum {
    N00B_CG_I8,
    N00B_CG_I16,
    N00B_CG_I32,
    N00B_CG_I64,
    N00B_CG_U8,
    N00B_CG_U16,
    N00B_CG_U32,
    N00B_CG_U64,
    N00B_CG_F32,
    N00B_CG_F64,
    N00B_CG_STRING, /**< n00b_string_t *, represented as MIR_T_I64. */
    N00B_CG_LIST,   /**< n00b_list_t *, represented as MIR_T_I64. */
    N00B_CG_DICT,   /**< n00b_dict_t *, represented as MIR_T_I64. */
    N00B_CG_SET,    /**< n00b runtime set object, represented as MIR_T_I64. */
    N00B_CG_RESULT, /**< result[T] *, represented as MIR_T_I64. */
    N00B_CG_OPTION, /**< option[T] / maybe[T] *, represented as MIR_T_I64. */
    N00B_CG_FUNC,   /**< Function pointer, represented as MIR_T_I64. */
    N00B_CG_NIL,    /**< Nil value (nullptr), represented as MIR_T_I64. */
    N00B_CG_PTR,    /**< Generic/unknown pointer, represented as MIR_T_I64. */
    N00B_CG_BOOL,   /**< Backed by I64, semantically boolean. */
    N00B_CG_VOID,   /**< No value (void return). */
} n00b_cg_type_tag_t;

// ============================================================================
// Value kind
// ============================================================================

/** @brief Discriminator for codegen value handles. */
typedef enum {
    N00B_CG_VAL_REG,   /**< MIR register. */
    N00B_CG_VAL_IMM,   /**< Immediate constant. */
    N00B_CG_VAL_MEM,   /**< Memory reference. */
    N00B_CG_VAL_LABEL, /**< Label handle. */
    N00B_CG_VAL_VOID,  /**< No value (void return, etc.). */
} n00b_cg_val_kind_t;

// ============================================================================
// Value handle (16 bytes, pass by value)
// ============================================================================

/**
 * @brief A codegen value handle.
 *
 * Wraps a MIR register, immediate, memory reference, or label.
 * Designed to be passed by value (16 bytes).
 */
typedef struct {
    uint32_t id;       /**< MIR_reg_t or label index. */
    uint8_t  kind;     /**< n00b_cg_val_kind_t. */
    uint8_t  type_tag; /**< n00b_cg_type_tag_t. */
    uint16_t _pad;
    uint64_t aux;      /**< Immediate value, displacement, or label handle. */
} n00b_cg_val_t;

/** @brief Sentinel void value. */
#define N00B_CG_VOID_VAL ((n00b_cg_val_t){.kind = N00B_CG_VAL_VOID, .type_tag = N00B_CG_VOID})

// ============================================================================
// Semantic operation codes
// ============================================================================

/**
 * @brief Semantic operation codes for auto-inferred operators.
 *
 * These are mapped to specific MIR instructions based on the operand
 * type tag (integer vs float, signed vs unsigned).
 */
typedef enum {
    N00B_CG_OP_ADD,
    N00B_CG_OP_SUB,
    N00B_CG_OP_MUL,
    N00B_CG_OP_DIV,
    N00B_CG_OP_MOD,
    N00B_CG_OP_NEG,
    N00B_CG_OP_AND,
    N00B_CG_OP_OR,
    N00B_CG_OP_XOR,
    N00B_CG_OP_NOT,
    N00B_CG_OP_SHL,
    N00B_CG_OP_SHR,
    N00B_CG_OP_EQ,
    N00B_CG_OP_NE,
    N00B_CG_OP_LT,
    N00B_CG_OP_LE,
    N00B_CG_OP_GT,
    N00B_CG_OP_GE,
    N00B_CG_OP_LOGICAL_AND,
    N00B_CG_OP_LOGICAL_OR,
    N00B_CG_OP_LOGICAL_NOT,
    N00B_CG_OP_COUNT, /**< Sentinel; custom ops start here. */
} n00b_cg_semantic_op_t;

// ============================================================================
// Storage policy
// ============================================================================

/** @brief How a variable should be stored. */
typedef enum {
    N00B_CG_STORE_REG, /**< In a MIR register. */
    N00B_CG_STORE_MEM, /**< In memory (alloca). */
} n00b_cg_storage_t;

// ============================================================================
// Module state
// ============================================================================

/** @brief Lifecycle state of a codegen module. */
typedef enum {
    N00B_CG_MOD_BUILDING, /**< Accepting emit operations. */
    N00B_CG_MOD_FINISHED, /**< MIR_finish_module called. */
    N00B_CG_MOD_LINKED,   /**< MIR_link called. */
    N00B_CG_MOD_COMPILED, /**< MIR_gen called, function pointers valid. */
} n00b_cg_module_state_t;

// ============================================================================
// Callback signatures
// ============================================================================

/**
 * @brief Type mapping callback: language type -> machine type tag.
 */
typedef n00b_cg_type_tag_t (*n00b_cg_type_map_fn)(n00b_cg_session_t *session,
                                                  n00b_tc_type_t    *type);

/**
 * @brief Per-NT codegen handler: emit code for a node, return result value.
 */
typedef n00b_cg_val_t (*n00b_cg_handler_fn)(n00b_cg_session_t *session,
                                            n00b_parse_tree_t *node);

/**
 * @brief Literal parser: token text -> immediate value.
 */
typedef n00b_cg_val_t (*n00b_cg_literal_fn)(n00b_cg_session_t *session,
                                            n00b_parse_tree_t *node,
                                            n00b_string_t     *lit_kind,
                                            n00b_cg_type_tag_t type_tag);

/**
 * @brief Storage policy: register vs memory per symbol.
 */
typedef n00b_cg_storage_t (*n00b_cg_storage_fn)(n00b_cg_session_t *session,
                                                n00b_sym_entry_t  *sym);

// ============================================================================
// Import table
// ============================================================================

/** @brief Type builder callback for FFI imports. */
typedef n00b_tc_type_t *(*n00b_cg_type_builder_fn)(n00b_tc_ctx_t *ctx);

/**
 * @brief A single FFI import entry.
 *
 * Describes an external C function that can be called from generated code.
 * Used both for manual imports and linker-section auto-registration.
 */
typedef struct {
    const char             *name;
    void                   *addr;
    n00b_cg_type_tag_t      ret;
    n00b_cg_type_tag_t     *param_types;
    int32_t                 n_params;
    bool                    is_vararg;
    n00b_cg_type_builder_fn type_builder;
    n00b_tc_type_t         *resolved_type;
} n00b_cg_import_entry_t;

/**
 * @brief Collection of FFI import entries.
 */
typedef struct {
    n00b_cg_import_entry_t *entries;
    int32_t                 count;
    int32_t                 cap;
} n00b_cg_import_table_t;

// ============================================================================
// Linker-section auto-registration macros
// ============================================================================

#ifdef __APPLE__
#define _N00B_FFI_SECTION __attribute__((section("__DATA,n00b_ffi"), used))
#else
#define _N00B_FFI_SECTION __attribute__((section("n00b_ffi"), used))
#endif

/**
 * @brief Export a C function for auto-registration as an FFI import.
 *
 * Places an `n00b_cg_import_entry_t` in a linker section that
 * `n00b_cg_collect_exports()` will scan at startup.
 *
 * @param sym        Symbol name (used as both the C variable suffix and the FFI name).
 * @param func_ptr   Function pointer to export.
 * @param ret_type   Return type tag (e.g., `N00B_CG_I64`).
 * @param builder    Type builder callback (or `NULL`).
 * @param ...        Parameter type tags (e.g., `N00B_CG_I64, N00B_CG_PTR`).
 */
#define N00B_CG_EXPORT(sym, func_ptr, ret_type, builder, ...)                                  \
    static n00b_cg_type_tag_t           _n00b_ffi_pt_##sym[]              = {__VA_ARGS__};     \
    static const n00b_cg_import_entry_t _n00b_ffi_##sym _N00B_FFI_SECTION = {                  \
        .name         = #sym,                                                                  \
        .addr         = (void *)(func_ptr),                                                    \
        .ret          = (ret_type),                                                            \
        .param_types  = _n00b_ffi_pt_##sym,                                                    \
        .n_params     = (int32_t)(sizeof(_n00b_ffi_pt_##sym) / sizeof(n00b_cg_type_tag_t)),    \
        .type_builder = (builder),                                                             \
    }

/** @brief Like N00B_CG_EXPORT but for zero-parameter functions. */
#define N00B_CG_EXPORT0(sym, func_ptr, ret_type, builder)                                      \
    static const n00b_cg_import_entry_t _n00b_ffi_##sym _N00B_FFI_SECTION = {                  \
        .name         = #sym,                                                                  \
        .addr         = (void *)(func_ptr),                                                    \
        .ret          = (ret_type),                                                            \
        .param_types  = NULL,                                                                  \
        .n_params     = 0,                                                                     \
        .type_builder = (builder),                                                             \
    }

// ============================================================================
// Audit result
// ============================================================================

/**
 * @brief Pre-flight audit result showing codegen coverage.
 *
 * Each NT in the grammar is classified as explicit (has a registered
 * handler), auto-inferred (has semantic annotations), or unhandled.
 */
typedef struct {
    const char **unhandled_nts;    /**< NT names with no handler or inference. */
    int32_t      unhandled_count;
    const char **auto_inferred;    /**< NT names handled by auto-inference. */
    int32_t      auto_inferred_count;
    const char **explicit_handled; /**< NT names with explicit handlers. */
    int32_t      explicit_count;
} n00b_cg_audit_t;

// ============================================================================
// Session lifecycle
// ============================================================================

/**
 * @brief Create a new codegen session.
 *
 * A session holds a persistent MIR context and supports incremental
 * compilation of multiple modules. For REPL use, create one session
 * at startup and reuse it for every expression.
 *
 * @param grammar  Grammar for tree-walking codegen (NULL for builder-only mode).
 *
 * @kw imports         Pre-built import table (NULL = empty; use n00b_cg_collect_exports()).
 * @kw type_map        Type mapping callback (NULL = everything is I64).
 * @kw literal_parser  Literal parsing callback (NULL = strtoll/strtod).
 * @kw storage_policy  Storage policy callback (NULL = all registers).
 * @kw default_handler Default handler for unregistered NTs (NULL = lower children).
 * @kw user_data       User-defined context pointer (NULL).
 * @kw embed_registry  Pre-built embed handler registry (NULL = allocate new).
 */
n00b_cg_session_t *
n00b_cg_session_new(n00b_grammar_t *grammar) _kargs
{
    n00b_cg_import_table_t *imports;
    n00b_cg_type_map_fn     type_map;
    n00b_cg_literal_fn      literal_parser;
    n00b_cg_storage_fn      storage_policy;
    n00b_cg_handler_fn      default_handler;
    void                   *user_data;
    n00b_dict_untyped_t    *embed_registry;
};

/**
 * @brief Free a session and all associated MIR state.
 */
void n00b_cg_session_free(n00b_cg_session_t *session);

// ============================================================================
// Backward-compatible lifecycle aliases
// ============================================================================

/**
 * @brief Create a codegen session (old API name).
 *
 * Equivalent to `n00b_cg_session_new()` but with the old parameter names.
 * Creates a session and an initial module named `module_name` (default "main").
 */
n00b_codegen_t *
n00b_codegen_new(n00b_grammar_t *grammar) _kargs
{
    n00b_annot_result_t *annot;
    n00b_cg_type_map_fn  type_map;
    n00b_cg_literal_fn   literal_parser;
    n00b_cg_storage_fn   storage_policy;
    n00b_cg_handler_fn   default_handler;
    void                *user_data;
    const char          *module_name;
};

/** @brief Free a codegen session (old API name). */
void n00b_codegen_free(n00b_codegen_t *cg);

// ============================================================================
// Module lifecycle
// ============================================================================

/**
 * @brief Create a new module within a session.
 *
 * Each module gets its own MIR module. Emit operations target the
 * session's active module (set via `n00b_cg_set_active_module` or
 * automatically when creating a module).
 *
 * @param session  Codegen session.
 * @param name     Module name (e.g., "repl_0", "mypackage.mymod").
 * @return The new module (also set as the session's active module).
 */
n00b_cg_module_t *n00b_cg_module_new(n00b_cg_session_t *session, const char *name);

/**
 * @brief Finish, link, and JIT-compile a module.
 *
 * After calling this, the module's functions are callable via their
 * JIT-compiled pointers.
 *
 * @param module      The module to compile.
 * @param entry_func  Name of the entry function to return a pointer to (or NULL).
 * @return Function pointer for `entry_func`, or NULL if no entry or on error.
 */
void *n00b_cg_module_compile(n00b_cg_module_t *module, const char *entry_func);

/**
 * @brief Set the active module for emit operations.
 */
void n00b_cg_set_active_module(n00b_cg_session_t *session, n00b_cg_module_t *module);

/**
 * @brief Set the annotation result on a module (for tree-walk codegen).
 */
void n00b_cg_module_set_annot(n00b_cg_module_t *module, n00b_annot_result_t *annot);

// ============================================================================
// Eval convenience (REPL primary path)
// ============================================================================

/**
 * @brief Evaluate a parse tree within a session.
 *
 * Creates a new module, wraps the tree in a function, compiles
 * incrementally, executes, and returns the result.
 *
 * @param session  Persistent codegen session.
 * @param tree     Parse tree to evaluate.
 *
 * @kw annot      Annotation walk result (NULL).
 * @kw func_name  Name for the wrapper function ("_eval").
 * @kw ok         If non-NULL, set to true on success, false on error.
 *
 * @return The int64_t result of execution (0 on error).
 */
int64_t
n00b_cg_session_eval_tree(n00b_cg_session_t *session, n00b_parse_tree_t *tree) _kargs
{
    n00b_annot_result_t *annot;
    const char          *func_name;
    bool                *ok;
    n00b_cg_type_tag_t  *out_type; /**< Out: type tag of last expression. */
};

// ============================================================================
// Module-level run (whole-file execution)
// ============================================================================

/**
 * @brief Compile and execute a whole module (file) with two-pass codegen.
 *
 * Pass 1 emits top-level function definitions as standalone MIR functions.
 * Pass 2 wraps remaining top-level statements in an entry function, compiles,
 * and executes it.
 *
 * @param session  Persistent codegen session.
 * @param tree     Parse tree for the entire module.
 *
 * @kw annot       Annotation walk result (NULL).
 * @kw entry_name  Name for the entry function ("_main").
 * @kw ok          If non-NULL, set to true on success, false on error.
 *
 * @return The int64_t result of execution (0 on error).
 */
int64_t
n00b_cg_session_run_module(n00b_cg_session_t *session, n00b_parse_tree_t *tree) _kargs
{
    n00b_annot_result_t *annot;
    const char          *entry_name;
    bool                *ok;
};

// ============================================================================
// Handler registration (on session, shared across modules)
// ============================================================================

/**
 * @brief Register a codegen handler by NT name.
 * @return True if NT was found in grammar, false otherwise.
 */
bool n00b_codegen_register(n00b_cg_session_t *session,
                           const char        *nt_name,
                           n00b_cg_handler_fn handler);

/**
 * @brief Register a codegen handler by NT id.
 * @return True if NT id is valid, false otherwise.
 */
bool n00b_codegen_register_by_id(n00b_cg_session_t *session,
                                 int64_t            nt_id,
                                 n00b_cg_handler_fn handler);

/**
 * @brief Register an operator token -> semantic op mapping.
 */
void n00b_codegen_map_operator(n00b_cg_session_t    *session,
                               const char           *token_text,
                               n00b_cg_semantic_op_t op);

// ============================================================================
// Pre-flight audit
// ============================================================================

n00b_cg_audit_t n00b_codegen_audit(n00b_cg_session_t *session);
void            n00b_cg_audit_free(n00b_cg_audit_t *audit);

// ============================================================================
// Operator lookup (for testing / handler use)
// ============================================================================

int32_t n00b_cg_lookup_op(n00b_cg_session_t *session, const char *text);

// ============================================================================
// Code emission (tree-walking)
// ============================================================================

/**
 * @brief Emit code for an entire parse tree.
 *
 * @pre Session must have a grammar and annotation result.
 */
bool n00b_codegen_emit(n00b_cg_session_t *session, n00b_parse_tree_t *tree);

/**
 * @brief Lower a single child node (for use within handlers).
 */
n00b_cg_val_t n00b_codegen_lower(n00b_cg_session_t *session, n00b_parse_tree_t *child);

// ============================================================================
// Queries (for use in handlers)
// ============================================================================

n00b_cg_type_tag_t n00b_codegen_node_type(n00b_cg_session_t *session, n00b_parse_tree_t *node);

/**
 * @brief Get the full type-checker type for a parse tree node.
 *
 * Unlike `n00b_codegen_node_type` which flattens to a tag, this returns
 * the raw `n00b_tc_type_t *` from the annotation result. Useful when
 * codegen needs the inner type parameter (e.g., T in result[T]).
 *
 * @return The resolved type, or NULL if not found.
 */
n00b_tc_type_t *n00b_codegen_node_tc_type(n00b_cg_session_t *session, n00b_parse_tree_t *node);

n00b_cf_label_t *n00b_codegen_cf_label(n00b_cg_session_t *session, n00b_parse_tree_t *node);

n00b_grammar_t      *n00b_codegen_grammar(n00b_cg_session_t *session);
n00b_annot_result_t *n00b_codegen_annot(n00b_cg_session_t *session);

/**
 * @brief Set (or replace) the session-level annotation result.
 *
 * Returns the previous value so callers can restore it.
 */
n00b_annot_result_t *n00b_codegen_set_annot(n00b_cg_session_t   *session,
                                            n00b_annot_result_t *annot);
n00b_diag_ctx_t     *n00b_codegen_diagnostics(n00b_cg_session_t *session);
void                *n00b_codegen_get_user_data(n00b_cg_session_t *session);

// ============================================================================
// Builder API: Function scope
// ============================================================================

void
n00b_cg_begin_func(n00b_cg_session_t *session, const char *name) _kargs
{
    n00b_cg_type_tag_t  ret;
    const char        **param_names;
    n00b_cg_type_tag_t *param_types;
    int32_t             n_params;
    bool                is_vararg;
};

void n00b_cg_end_func(n00b_cg_session_t *session);

n00b_cg_val_t n00b_cg_param(n00b_cg_session_t *session, int32_t index);

// ============================================================================
// Builder API: Locals
// ============================================================================

n00b_cg_val_t
n00b_cg_local(n00b_cg_session_t *session, const char *name) _kargs
{
    n00b_cg_type_tag_t type;
};

void          n00b_cg_store(n00b_cg_session_t *session, n00b_cg_val_t dst, n00b_cg_val_t src);
n00b_cg_val_t n00b_cg_load(n00b_cg_session_t *session, n00b_cg_val_t var);

// ============================================================================
// Builder API: Constants
// ============================================================================

#define n00b_cg_const(cg, value)                                                               \
    _Generic((value),                                                                          \
        int64_t: _n00b_cg_const_i64,                                                           \
        int32_t: _n00b_cg_const_i32,                                                           \
        uint64_t: _n00b_cg_const_u64,                                                          \
        double: _n00b_cg_const_f64,                                                            \
        float: _n00b_cg_const_f32,                                                             \
        bool: _n00b_cg_const_bool,                                                             \
        void *: _n00b_cg_const_ptr,                                                            \
        default: _n00b_cg_const_i64)(cg, value)

n00b_cg_val_t _n00b_cg_const_i64(n00b_cg_session_t *s, int64_t v);
n00b_cg_val_t _n00b_cg_const_i32(n00b_cg_session_t *s, int32_t v);
n00b_cg_val_t _n00b_cg_const_u64(n00b_cg_session_t *s, uint64_t v);
n00b_cg_val_t _n00b_cg_const_f64(n00b_cg_session_t *s, double v);
n00b_cg_val_t _n00b_cg_const_f32(n00b_cg_session_t *s, float v);
n00b_cg_val_t _n00b_cg_const_bool(n00b_cg_session_t *s, bool v);
n00b_cg_val_t _n00b_cg_const_ptr(n00b_cg_session_t *s, void *v);

// ============================================================================
// Builder API: Arithmetic / logic
// ============================================================================

n00b_cg_val_t n00b_cg_emit_add(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);
n00b_cg_val_t n00b_cg_emit_sub(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);
n00b_cg_val_t n00b_cg_emit_mul(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);
n00b_cg_val_t n00b_cg_emit_div(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);
n00b_cg_val_t n00b_cg_emit_mod(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);
n00b_cg_val_t n00b_cg_emit_neg(n00b_cg_session_t *s, n00b_cg_val_t a);

n00b_cg_val_t n00b_cg_emit_and(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);
n00b_cg_val_t n00b_cg_emit_or(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);
n00b_cg_val_t n00b_cg_emit_xor(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);
n00b_cg_val_t n00b_cg_emit_not(n00b_cg_session_t *s, n00b_cg_val_t a);
n00b_cg_val_t n00b_cg_emit_shl(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);
n00b_cg_val_t n00b_cg_emit_shr(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);

n00b_cg_val_t n00b_cg_emit_eq(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);
n00b_cg_val_t n00b_cg_emit_ne(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);
n00b_cg_val_t n00b_cg_emit_lt(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);
n00b_cg_val_t n00b_cg_emit_le(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);
n00b_cg_val_t n00b_cg_emit_gt(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);
n00b_cg_val_t n00b_cg_emit_ge(n00b_cg_session_t *s, n00b_cg_val_t a, n00b_cg_val_t b);

n00b_cg_val_t
n00b_cg_emit_convert(n00b_cg_session_t *s, n00b_cg_val_t src, n00b_cg_type_tag_t dst_type);

// ============================================================================
// Builder API: Control flow
// ============================================================================

n00b_cg_val_t n00b_cg_label_new(n00b_cg_session_t *session);
void          n00b_cg_label_here(n00b_cg_session_t *session, n00b_cg_val_t label);

void n00b_cg_emit_jmp(n00b_cg_session_t *session, n00b_cg_val_t label);
void n00b_cg_emit_bt(n00b_cg_session_t *session, n00b_cg_val_t cond, n00b_cg_val_t label);
void n00b_cg_emit_bf(n00b_cg_session_t *session, n00b_cg_val_t cond, n00b_cg_val_t label);

void n00b_cg_emit_ret(n00b_cg_session_t *session, n00b_cg_val_t val);
void n00b_cg_emit_ret_void(n00b_cg_session_t *session);

// ============================================================================
// Builder API: Function calls
// ============================================================================

n00b_cg_val_t
n00b_cg_emit_call(n00b_cg_session_t *session,
                  const char        *func_name,
                  n00b_cg_val_t     *args,
                  int32_t            n_args) _kargs
{
    n00b_cg_type_tag_t ret;
};

n00b_cg_val_t
n00b_cg_emit_call_indirect(n00b_cg_session_t *session,
                           n00b_cg_val_t      func_ptr,
                           n00b_cg_val_t     *args,
                           int32_t            n_args) _kargs
{
    n00b_cg_type_tag_t ret;
};

// ============================================================================
// Builder API: Memory
// ============================================================================

n00b_cg_val_t
n00b_cg_emit_mem_load(n00b_cg_session_t *session,
                      n00b_cg_val_t      addr,
                      n00b_cg_type_tag_t type) _kargs
{
    int64_t offset;
};

void
n00b_cg_emit_mem_store(n00b_cg_session_t *session,
                       n00b_cg_val_t      addr,
                       n00b_cg_val_t      value) _kargs
{
    int64_t offset;
};

n00b_cg_val_t n00b_cg_emit_alloca(n00b_cg_session_t *session, int64_t size);

// ============================================================================
// Builder API: Imports (per-module, for backward compat)
// ============================================================================

void
n00b_cg_import_func(n00b_cg_session_t *session, const char *name, void *addr) _kargs
{
    n00b_cg_type_tag_t  ret;
    n00b_cg_type_tag_t *param_types;
    int32_t             n_params;
    bool                is_vararg;
};

// ============================================================================
// Import table management
// ============================================================================

/**
 * @brief Collect all FFI exports from linker sections.
 *
 * Scans the `n00b_ffi` linker section for `n00b_cg_import_entry_t` entries
 * placed by `N00B_CG_EXPORT` macros and returns them as a table.
 */
n00b_cg_import_table_t *n00b_cg_collect_exports(void);

n00b_cg_import_table_t *n00b_cg_import_table_new(void);
void n00b_cg_import_table_add(n00b_cg_import_table_t *table, n00b_cg_import_entry_t entry);
void n00b_cg_import_table_free(n00b_cg_import_table_t *table);

/**
 * @brief Resolve n00b type-checker types for all entries with a type_builder.
 */
void n00b_cg_import_table_resolve_types(n00b_cg_import_table_t *table, n00b_tc_ctx_t *ctx);

// ============================================================================
// Execution modes (backward compat — operate on session's initial module)
// ============================================================================

bool n00b_codegen_interpret(n00b_cg_session_t *session,
                            const char        *func_name,
                            void              *result,
                            void              *args,
                            int32_t            n_args);

void *n00b_codegen_jit(n00b_cg_session_t *session, const char *func_name);

void n00b_codegen_dump(n00b_cg_session_t *session, FILE *f);

// ============================================================================
// Convenience helpers (backward compat)
// ============================================================================

bool
n00b_cg_emit_func_from_tree(n00b_cg_session_t *session,
                            n00b_parse_tree_t *tree,
                            const char        *func_name) _kargs
{
    n00b_cg_type_tag_t  ret;
    n00b_cg_type_tag_t *result_type; /**< Out: type of last expression. */
};

int64_t
n00b_codegen_eval_tree(n00b_grammar_t *grammar, n00b_parse_tree_t *tree) _kargs
{
    n00b_annot_result_t *annot;
    n00b_cg_type_map_fn  type_map;
    const char          *func_name;
    bool                *ok;
};

// ============================================================================
// Cross-module symbol resolution
// ============================================================================

/**
 * @brief Merge a module's public symbols into the session's global scope.
 *
 * Walks the module's annotation symtab and adds non-private functions
 * to `session->global_scope` so they're visible to subsequent modules.
 */
void n00b_cg_session_merge_module(n00b_cg_session_t *s, n00b_cg_module_t *m);

/**
 * @brief Look up a symbol in a module's annotation symtab.
 * @return The entry, or NULL if not found.
 */
n00b_sym_entry_t *n00b_cg_module_lookup(n00b_cg_module_t *m, const char *name);

/**
 * @brief Find a cached module by fully-qualified name.
 * @return The module, or nullptr if not in cache.
 */
n00b_cg_module_t *n00b_cg_session_find_module(n00b_cg_session_t *s, n00b_string_t *fqn);

// ============================================================================
// Side-table: per-value typehash for registry-driven method dispatch
// ============================================================================

/**
 * @brief Record the runtime typehash for a codegen value.
 *
 * Stores the typehash in a per-session side-table keyed by the value's
 * `(kind, id)` pair so it can be retrieved later for extension-method
 * dispatch via the type registry. Callers should invoke this only at
 * sites that *know* the user-defined typehash (function parameters,
 * class constructor results, postfix-`.` method results).
 *
 * @param session    Codegen session.
 * @param val        The codegen value whose typehash is being recorded.
 * @param type_hash  The typehash (0 is treated as a no-op).
 *
 * @kw allocator  Allocator used on the (lazy) first-call side-table
 *                allocation. nullptr = runtime default. (default: nullptr)
 */
extern void n00b_cg_val_set_type_hash(n00b_cg_session_t *session,
                                     n00b_cg_val_t      val,
                                     uint64_t           type_hash) _kargs {
    n00b_allocator_t *allocator = nullptr;
};

/**
 * @brief Look up the recorded typehash for a codegen value.
 *
 * Returns 0 when no typehash has been recorded for this value. The
 * dispatch code falls back to `type_tag_to_hash(val.type_tag)` for
 * primitives in that case.
 *
 * @param session  Codegen session.
 * @param val      The codegen value to look up.
 * @return         The recorded typehash, or 0 if none.
 */
extern uint64_t n00b_cg_val_get_type_hash(n00b_cg_session_t *session,
                                         n00b_cg_val_t      val);

// ============================================================================
// Session debug/dump
// ============================================================================

void n00b_cg_session_dump(n00b_cg_session_t *session, FILE *out);
