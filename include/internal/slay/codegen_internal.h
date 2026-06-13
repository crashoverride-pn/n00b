#pragma once

/**
 * @file codegen_internal.h
 * @internal
 * @brief Internal structs for the codegen engine: session and module state.
 */

#include "slay/codegen.h"
#include "slay/symtab.h"
#include "internal/slay/grammar_internal.h"
#include "adt/dict.h"
#include "adt/dict_untyped.h"
#include "core/string.h"

typedef struct n00b_rt_callback_t n00b_rt_callback_t;

// ============================================================================
// Operator mapping entry
// ============================================================================

typedef struct {
    const char           *text;
    n00b_cg_semantic_op_t op;
} n00b_cg_op_entry_t;

typedef struct {
    n00b_cg_module_t **modules;
    int32_t            count;
    int32_t            cap;
} n00b_cg_private_func_index_t;

typedef struct {
    n00b_rt_callback_t *callback;
    n00b_cg_module_t   *module;
    n00b_parse_tree_t  *site;
    bool                reported_unresolved;
} n00b_cg_runtime_callback_ref_t;

// ============================================================================
// Loop label stack entry
// ============================================================================

typedef struct {
    n00b_cg_val_t break_label;
    n00b_cg_val_t continue_label;
} n00b_cg_loop_entry_t;

// ============================================================================
// Import record (for MIR_CALL proto caching)
// ============================================================================

typedef struct {
    const char *name;
    MIR_item_t  proto;
    MIR_item_t  import;
    void       *addr;
} n00b_cg_import_t;

// ============================================================================
// Module: per-file or per-REPL-expression compilation unit
// ============================================================================

struct n00b_cg_module_t {
    n00b_cg_session_t     *session;
    const char            *name; // FQN: "package.module" or "repl_N"
    MIR_module_t           mir_module;
    n00b_cg_module_state_t state;

    // Annotation result (set per-module for tree-walk codegen)
    n00b_annot_result_t *annot;

    // Functions defined in this module
    MIR_item_t  *func_protos;
    const char **func_names;
    int32_t      func_proto_count;
    int32_t      func_proto_cap;
    const char **private_func_names;
    int32_t      private_func_count;
    int32_t      private_func_cap;

    // Per-module imports (for MIR linking)
    n00b_cg_import_t *imports;
    int32_t           import_count;
    int32_t           import_cap;

    // Per-module emit state (reset each function / module)
    MIR_label_t          *labels;
    int32_t               label_count;
    int32_t               label_cap;
    n00b_cg_loop_entry_t *loop_stack;
    int32_t               loop_depth;
    int32_t               loop_cap;
    int32_t               temp_counter;
    MIR_item_t            cur_func; // function being emitted into
};

// ============================================================================
// Session: persistent state across all modules
// ============================================================================

struct n00b_cg_session_t {
    // MIR context (single, persistent)
    MIR_context_t mir_ctx;
    bool          gen_inited;

    // Grammar & callbacks (shared across all modules)
    n00b_grammar_t     *grammar;
    n00b_cg_type_map_fn type_map;
    n00b_cg_literal_fn  literal_parser;
    n00b_cg_storage_fn  storage_policy;
    n00b_cg_handler_fn  default_handler;

    // Handler table: indexed by NT id (shared)
    n00b_cg_handler_fn *handlers;
    int32_t             handler_cap;

    // Operator mapping: small array, linear scan (shared)
    n00b_cg_op_entry_t *op_map;
    int32_t             op_map_count;
    int32_t             op_map_cap;

    // FFI import table (from N00B_CG_EXPORT / manual registration)
    n00b_cg_import_table_t *import_table;

    // All modules in this session (compilation order)
    n00b_cg_module_t **modules;
    int32_t            module_count;
    int32_t            module_cap;

    // Active module: target for all emit operations
    n00b_cg_module_t *active_module;

    // Backward compat: annotation result stored on session for old API
    n00b_annot_result_t *annot;

    // Module cache: C-string FQN → n00b_cg_module_t * (for use-stmt loading)
    n00b_dict_untyped_t *module_cache;

    // Function metadata: "module-identity:function" → codegen-private signature record.
    n00b_dict_untyped_t *func_meta;

    // Private function index: function name -> modules that define it privately.
    n00b_dict_untyped_t *private_func_index;

    // Local value metadata: "module-identity:function:name" → semantic n00b_cg_type_tag_t + 1.
    n00b_dict_untyped_t *local_types;

    // Local record/tuple layout metadata: "module-identity:function:name" ->
    // n00b_class_layout_t *.
    n00b_dict_untyped_t *local_layouts;

    // Local callback metadata: "module-identity:function:name" -> n00b_rt_callback_t *.
    n00b_dict_untyped_t *local_callbacks;

    // Runtime callbacks emitted by callback literals in this session.
    n00b_cg_runtime_callback_ref_t *runtime_callbacks;
    int32_t                         runtime_callback_count;
    int32_t                         runtime_callback_cap;

    // Loading stack for cycle detection (modules currently being loaded),
    // keyed by resolved-path module identity.  Lazily created on first push.
    n00b_list_t(n00b_string_t *) *loading_stack;

    // Global scope: merged public symbols from all compiled modules
    n00b_symtab_t *global_scope;

    // Embed literal handler registry (modifier name → n00b_embed_handler_t *)
    n00b_dict_untyped_t *embed_registry;

    // Compile-time variable store (comptime {} blocks).
    // Maps C-string name → void * (managed objects).
    n00b_dict_untyped_t *comptime_vars;
    bool                 in_comptime;

    // Side-table mapping a `(kind, id)` packed key for a `n00b_cg_val_t`
    // to a typehash for registry-driven extension-method dispatch.
    // Populated only at the small set of sites that *know* the
    // user-defined opaque typehash (function params, class ctors,
    // postfix-`.` method results). All other values miss this lookup
    // and the dispatch falls back to the hardcoded primitive switch
    // in `type_tag_to_hash`. Keyed by uint64_t = (kind << 56) | id;
    // value is the typehash stored as a void* (uintptr_t cast).
    n00b_dict_untyped_t *value_typehashes;

    // Active function context used while lowering bodies.
    uint64_t           current_once_key;
    n00b_cg_type_tag_t current_func_ret_type;
    bool               current_attr_lock_on_write;
    bool               reject_unconsumed_yield;

    // Diagnostics
    n00b_diag_ctx_t *diag;
    bool             has_codegen_errors;
    void            *user_data;
};

// ============================================================================
// Internal helpers (codegen_mir.c)
// ============================================================================

MIR_type_t n00b_cg_mir_type(n00b_cg_type_tag_t tag);

MIR_op_t n00b_cg_mir_op(n00b_cg_session_t *session, n00b_cg_val_t val);

n00b_cg_val_t n00b_cg_temp(n00b_cg_session_t *session, n00b_cg_type_tag_t type);

n00b_cg_val_t n00b_cg_emit_binop(n00b_cg_session_t    *session,
                                 n00b_cg_semantic_op_t op,
                                 n00b_cg_val_t         a,
                                 n00b_cg_val_t         b);

n00b_cg_val_t
n00b_cg_emit_unop(n00b_cg_session_t *session, n00b_cg_semantic_op_t op, n00b_cg_val_t a);

MIR_item_t n00b_cg_get_or_create_proto(n00b_cg_session_t  *session,
                                       const char         *name,
                                       n00b_cg_type_tag_t  ret,
                                       n00b_cg_type_tag_t *param_types,
                                       int32_t             n_params,
                                       bool                is_vararg);

n00b_cg_import_t *n00b_cg_find_import(n00b_cg_session_t *session, const char *name);

MIR_item_t n00b_cg_find_func(n00b_cg_session_t *session, const char *name);
bool n00b_cg_func_is_private_in_other_module(n00b_cg_session_t *session, const char *name);
void n00b_cg_module_mark_private_func(n00b_cg_module_t *module, const char *name);
bool n00b_cg_module_func_is_private(n00b_cg_module_t *module, const char *name);
