/**
 * @file codegen.c
 * @brief Code generation engine: session/module lifecycle, tree walk, auto-inference, audit.
 *
 * This is the core codegen engine that walks a parse tree, dispatching
 * to registered handlers and auto-inferred codegen based on grammar
 * annotations (@operator, @literal, @branch, @loop, etc.).
 */

#include "n00b.h"
// For n00b_get_runtime()->system_pool — the non-moving, permanent pool
// JIT string literals are allocated from (see default_literal_parser).
#include "core/runtime.h"
#include "internal/slay/codegen_internal.h"
#include "n00b/n00b_compile_binary.h"
#include "n00b/embed.h"
#include "n00b/embed_ffi.h"
#include "slay/codegen_builtins.h"
#include "core/alloc.h"
#include "core/data_lock.h"
#include "core/hash.h"
#include "core/type_info.h"
#include "text/strings/format.h"         // n00b_cformat
#include "text/strings/string_convert.h" // n00b_unicode_str_to_cstr (MIR edge)
#include "typecheck/unify.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static FILE *
n00b_mir_open_code_len_trace(void)
{
    return tmpfile();
}

static void
n00b_mir_enable_code_len_trace(MIR_context_t ctx, FILE *trace)
{
#if !MIR_NO_GEN_DEBUG
    if (trace) {
        MIR_gen_set_debug_file(ctx, trace);
        MIR_gen_set_debug_level(ctx, 0);
    }
#else
    (void)ctx;
    (void)trace;
#endif
}

static bool
n00b_mir_finish_code_len_trace(MIR_context_t ctx,
                               FILE         *trace,
                               size_t       *code_lens,
                               size_t        func_count)
{
#if MIR_NO_GEN_DEBUG
    (void)ctx;
    (void)code_lens;
    (void)func_count;

    if (trace) {
        fclose(trace);
    }

    return false;
#else
    if (!trace) {
        return false;
    }

    fflush(trace);
    MIR_gen_set_debug_file(ctx, NULL);
    MIR_gen_set_debug_level(ctx, 100);

    rewind(trace);

    size_t found = 0;
    char   line[4096];

    while (fgets(line, sizeof(line), trace)) {
        char *p = strstr(line, " len=");

        if (!p) {
            continue;
        }

        p += 5;

        char              *end    = NULL;
        unsigned long long parsed = strtoull(p, &end, 10);

        if (end != p && *end == ')') {
            if (found < func_count) {
                code_lens[found] = (size_t)parsed;
            }

            found++;
        }
    }

    fclose(trace);

    return found == func_count;
#endif
}

// ============================================================================
// Default built-in operator table
// ============================================================================

static const struct {
    const char           *text;
    n00b_cg_semantic_op_t op;
} default_ops[] = {
    {"+", N00B_CG_OP_ADD},         {"-", N00B_CG_OP_SUB},
    {"*", N00B_CG_OP_MUL},         {"/", N00B_CG_OP_DIV},
    {"%", N00B_CG_OP_MOD},         {"&", N00B_CG_OP_AND},
    {"|", N00B_CG_OP_OR},          {"^", N00B_CG_OP_XOR},
    {"<<", N00B_CG_OP_SHL},        {">>", N00B_CG_OP_SHR},
    {"==", N00B_CG_OP_EQ},         {"!=", N00B_CG_OP_NE},
    {"<", N00B_CG_OP_LT},          {"<=", N00B_CG_OP_LE},
    {">", N00B_CG_OP_GT},          {">=", N00B_CG_OP_GE},
    {"!", N00B_CG_OP_LOGICAL_NOT}, {"&&", N00B_CG_OP_LOGICAL_AND},
    {"||", N00B_CG_OP_LOGICAL_OR}, {"and", N00B_CG_OP_LOGICAL_AND},
    {"or", N00B_CG_OP_LOGICAL_OR},
};

#define NUM_DEFAULT_OPS (sizeof(default_ops) / sizeof(default_ops[0]))

// ============================================================================
// Forward declarations for NT handlers registered during session init
// ============================================================================

static n00b_cg_val_t codegen_func_def(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_assert_stmt(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_comptime(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_enum_stmt(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_class_decl(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_tuple(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_list(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_dict_or_set(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_use_stmt(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_parameter_block(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_confspec_block(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_interface_decl(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_callback_lit(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_extern_block(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_lock_attr_stmt(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_yield_stmt(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_expression_stmt(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_block_value_expr(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_if_value_expr(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_switch_value_expr(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_walk(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_class_layout_t *compute_class_layout(n00b_cg_session_t *s, n00b_scope_t *scope);
static void                *n00b_builtin_obj_alloc(int64_t size);
static uint64_t             n00b_builtin_field_get(void *obj, int64_t offset);
static void                 n00b_builtin_field_set(void *obj, int64_t offset, uint64_t value);
static void n00b_builtin_field_set_and_lock(void *obj, int64_t offset, uint64_t value);
static int32_t
layout_field_index(n00b_class_layout_t *layout, const char *name, size_t name_len);
static void
codegen_error(n00b_cg_session_t *s, n00b_parse_tree_t *node, const char *code, const char *msg);
static n00b_cg_type_tag_t codegen_lookup_func_ret_type(n00b_cg_session_t *s,
                                                       const char        *func_name,
                                                       n00b_cg_type_tag_t fallback);
static void               codegen_fill_callback_signature(n00b_cg_session_t  *s,
                                                          const char         *func_name,
                                                          n00b_rt_callback_t *cb);
static void               codegen_register_runtime_callback(n00b_cg_session_t  *s,
                                                            n00b_rt_callback_t *cb,
                                                            n00b_parse_tree_t  *site);
static void               codegen_resolve_runtime_callbacks(n00b_cg_session_t *s);
static void               codegen_report_unresolved_runtime_callbacks(n00b_cg_session_t *s);
static bool               codegen_reject_private_cross_module_call(n00b_cg_session_t *s,
                                                                   n00b_parse_tree_t *site,
                                                                   const char        *func_name);

static bool
codegen_type_is_integer_like(n00b_cg_type_tag_t tag)
{
    switch (tag) {
    case N00B_CG_I8:
    case N00B_CG_I16:
    case N00B_CG_I32:
    case N00B_CG_I64:
    case N00B_CG_U8:
    case N00B_CG_U16:
    case N00B_CG_U32:
    case N00B_CG_U64:
    case N00B_CG_BOOL:
        return true;
    default:
        return false;
    }
}

static bool
codegen_token_is_terminal(n00b_cg_session_t *s,
                          n00b_token_info_t *tok,
                          const char        *terminal_name)
{
    if (!s || !s->grammar || !tok || !terminal_name) {
        return false;
    }

    size_t         terminal_len = strlen(terminal_name);
    n00b_string_t *tok_name     = n00b_get_terminal_name(s->grammar, tok->tid);

    if (tok_name && tok_name->u8_bytes == terminal_len
        && memcmp(tok_name->data, terminal_name, terminal_len) == 0) {
        return true;
    }

    n00b_string_t *name = n00b_string_from_cstr(terminal_name);
    int64_t        tid  = n00b_grammar_terminal_id(s->grammar, name);

    return tid != 0 && tok->tid == tid;
}

// ============================================================================
// Internal: install default operators on a session
// ============================================================================

static void
install_default_ops(n00b_cg_session_t *s)
{
    s->op_map_cap   = (int32_t)(NUM_DEFAULT_OPS + 16);
    s->op_map_count = (int32_t)NUM_DEFAULT_OPS;
    s->op_map       = n00b_alloc_array(n00b_cg_op_entry_t, (size_t)s->op_map_cap);

    for (int32_t i = 0; i < (int32_t)NUM_DEFAULT_OPS; i++) {
        s->op_map[i].text = default_ops[i].text;
        s->op_map[i].op   = default_ops[i].op;
    }
}

// ============================================================================
// Internal: install handler table from grammar
// ============================================================================

static void
install_handlers(n00b_cg_session_t *s)
{
    if (!s->grammar) {
        return;
    }

    int64_t nt_count = (int64_t)n00b_list_len(s->grammar->nt_list);

    if (nt_count > 0) {
        s->handler_cap = (int32_t)nt_count;
        s->handlers    = n00b_alloc_array(n00b_cg_handler_fn, (size_t)nt_count);
    }
}

// ============================================================================
// Session lifecycle
// ============================================================================

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
}
{
    n00b_cg_session_t *s = n00b_alloc(n00b_cg_session_t);

    s->grammar         = grammar;
    s->type_map        = kargs->type_map;
    s->literal_parser  = kargs->literal_parser;
    s->storage_policy  = kargs->storage_policy;
    s->default_handler = kargs->default_handler;
    s->user_data       = kargs->user_data;
    s->import_table    = kargs->imports;
    s->diag            = n00b_diag_ctx_new();
    s->global_scope    = n00b_symtab_new();

    // Embed handler registry (caller must provide via .embed_registry karg).
    s->embed_registry = kargs->embed_registry;

    // Module cache: C-string keyed dictionary for use-stmt loading.
    s->module_cache = n00b_alloc(n00b_dict_untyped_t);
    n00b_dict_untyped_init(s->module_cache, .hash = n00b_hash_cstring);

    // Function signature metadata used by keyword/default/varargs call binding.
    s->func_meta = n00b_alloc(n00b_dict_untyped_t);
    n00b_dict_untyped_init(s->func_meta, .hash = n00b_hash_cstring);

    s->private_func_index = n00b_alloc(n00b_dict_untyped_t);
    n00b_dict_untyped_init(s->private_func_index, .hash = n00b_hash_cstring);

    // Local variable semantic type metadata used when syntax-introduced
    // locals are not fully represented in the annotation type map.
    s->local_types = n00b_alloc(n00b_dict_untyped_t);
    n00b_dict_untyped_init(s->local_types, .hash = n00b_hash_cstring);

    s->local_layouts = n00b_alloc(n00b_dict_untyped_t);
    n00b_dict_untyped_init(s->local_layouts, .hash = n00b_hash_cstring);

    s->local_callbacks = n00b_alloc(n00b_dict_untyped_t);
    n00b_dict_untyped_init(s->local_callbacks, .hash = n00b_hash_cstring);

    // Initialize MIR context (single, persistent).
    s->mir_ctx = MIR_init();

    install_handlers(s);
    install_default_ops(s);

    // Register built-in NT handlers.
    if (grammar) {
        n00b_codegen_register(s, "func-def", codegen_func_def);
        n00b_codegen_register(s, "assert-stmt", codegen_assert_stmt);
        n00b_codegen_register(s, "comptime-stmt", codegen_comptime);
        n00b_codegen_register(s, "enum-stmt", codegen_enum_stmt);
        n00b_codegen_register(s, "class-decl", codegen_class_decl);
        n00b_codegen_register(s, "tuple-or-paren", codegen_tuple);
        n00b_codegen_register(s, "list-lit", codegen_list);
        n00b_codegen_register(s, "dict-or-set-lit", codegen_dict_or_set);
        n00b_codegen_register(s, "use-stmt", codegen_use_stmt);
        n00b_codegen_register(s, "parameter-block", codegen_parameter_block);
        n00b_codegen_register(s, "confspec-block", codegen_confspec_block);
        n00b_codegen_register(s, "interface-decl", codegen_interface_decl);
        n00b_codegen_register(s, "callback-lit", codegen_callback_lit);
        n00b_codegen_register(s, "extern-block", codegen_extern_block);
        n00b_codegen_register(s, "lock-attr-stmt", codegen_lock_attr_stmt);
        n00b_codegen_register(s, "yield-stmt", codegen_yield_stmt);
        n00b_codegen_register(s, "expression-stmt", codegen_expression_stmt);
        n00b_codegen_register(s, "block-value-expr", codegen_block_value_expr);
        n00b_codegen_register(s, "if-value-expr", codegen_if_value_expr);
        n00b_codegen_register(s, "switch-value-expr", codegen_switch_value_expr);
    }

    return s;
}

void
n00b_cg_session_free(n00b_cg_session_t *s)
{
    if (!s) {
        return;
    }

    if (s->mir_ctx) {
        // Finish any unfinished modules.
        for (int32_t i = 0; i < s->module_count; i++) {
            n00b_cg_module_t *m = s->modules[i];

            if (m && m->state == N00B_CG_MOD_BUILDING) {
                MIR_finish_module(s->mir_ctx);
                m->state = N00B_CG_MOD_FINISHED;
            }
        }

        if (s->gen_inited) {
            MIR_gen_finish(s->mir_ctx);
        }

        MIR_finish(s->mir_ctx);
    }

    if (s->diag) {
        n00b_diag_ctx_free(s->diag);
    }
}

// ============================================================================
// Backward-compatible lifecycle (old API)
// ============================================================================

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
}
{
    n00b_cg_session_t *s = n00b_cg_session_new(grammar,
                                               .type_map        = kargs->type_map,
                                               .literal_parser  = kargs->literal_parser,
                                               .storage_policy  = kargs->storage_policy,
                                               .default_handler = kargs->default_handler,
                                               .user_data       = kargs->user_data);

    // Store annotation result on session (old API pattern).
    s->annot = kargs->annot;

    // Create an initial module (old API always had one module).
    const char *mod_name = kargs->module_name ? kargs->module_name : "main";
    n00b_cg_module_new(s, mod_name);

    // Copy annot to the module too.
    if (s->active_module && kargs->annot) {
        s->active_module->annot = kargs->annot;
    }

    return s;
}

void
n00b_codegen_free(n00b_codegen_t *cg)
{
    n00b_cg_session_free(cg);
}

// ============================================================================
// Side-table: per-value typehash for registry-driven method dispatch
// ============================================================================
//
// Why a side-table (D-021 design): `n00b_cg_val_t` is exactly 16 bytes and
// shares its layout with `n00b_embed_result_t` (the embed-handler ABI).
// Two `_Static_assert(sizeof(val) == sizeof(result))` sites enforce this:
// one in `codegen.c` at the embed-dispatch return site, one in
// `embed_ffi.c` at the FFI module literal. Widening the struct would break
// both assertions and the public embed-handler ABI, so we keep typehashes
// out-of-band.
//
// Key encoding: `(kind << 56) | id`. The `id` field is a 32-bit MIR
// register or label index; `kind` fits in 8 bits. The two together
// uniquely identify a value within the active function. The side-table
// is keyed by `uint64_t` (FNV-1a hashed via `n00b_hash_word`), the same
// scheme used for `comptime_vars` on the session. Values are stored as
// `void *` (uintptr_t cast of the typehash); a missing entry returns 0.

static inline uint64_t
cg_val_typehash_key(n00b_cg_val_t v)
{
    return ((uint64_t)v.kind << 56) | (uint64_t)v.id;
}

static void
ensure_value_typehashes(n00b_cg_session_t *s, n00b_allocator_t *allocator)
{
    if (s->value_typehashes) {
        return;
    }

    s->value_typehashes = n00b_alloc(n00b_dict_untyped_t,
                                     .allocator = allocator);
    n00b_dict_untyped_init(s->value_typehashes,
                           .hash          = n00b_hash_word,
                           .skip_obj_hash = true,
                           .allocator     = allocator);
}

void
n00b_cg_val_set_type_hash(n00b_cg_session_t *s, n00b_cg_val_t v, uint64_t type_hash) _kargs
{
    n00b_allocator_t *allocator = nullptr;
}
{
    if (!s || type_hash == 0) {
        return;
    }

    // Only kinds with stable `(kind, id)` identity are recorded. IMM and
    // LABEL kinds reuse `id` across different semantic values, so we keep
    // them out to avoid cross-contamination.
    if (v.kind != N00B_CG_VAL_REG && v.kind != N00B_CG_VAL_MEM) {
        return;
    }

    ensure_value_typehashes(s, allocator);

    uint64_t key = cg_val_typehash_key(v);
    n00b_dict_untyped_put(s->value_typehashes, key, (void *)(uintptr_t)type_hash);
}

uint64_t
n00b_cg_val_get_type_hash(n00b_cg_session_t *s, n00b_cg_val_t v)
{
    if (!s || !s->value_typehashes) {
        return 0;
    }

    if (v.kind != N00B_CG_VAL_REG && v.kind != N00B_CG_VAL_MEM) {
        return 0;
    }

    uint64_t key   = cg_val_typehash_key(v);
    bool     found = false;
    void    *val   = n00b_dict_untyped_get(s->value_typehashes, key, &found);

    return found ? (uint64_t)(uintptr_t)val : 0;
}

// ============================================================================
// Module lifecycle
// ============================================================================

n00b_cg_module_t *
n00b_cg_module_new(n00b_cg_session_t *s, const char *name)
{
    n00b_cg_module_t *m = n00b_alloc(n00b_cg_module_t);

    m->session    = s;
    if (name) {
        size_t name_len = strlen(name) + 1;
        m->name         = n00b_alloc_array(char, name_len);
        memcpy(m->name, name, name_len);
    }
    m->mir_module = MIR_new_module(s->mir_ctx, name);
    m->state      = N00B_CG_MOD_BUILDING;

    // Add to session's module list.
    if (s->module_count >= s->module_cap) {
        int32_t            new_cap  = s->module_cap ? s->module_cap * 2 : 8;
        n00b_cg_module_t **new_mods = n00b_alloc_array(n00b_cg_module_t *, (size_t)new_cap);

        if (s->modules) {
            memcpy(new_mods, s->modules, sizeof(n00b_cg_module_t *) * (size_t)s->module_count);
        }

        s->modules    = new_mods;
        s->module_cap = new_cap;
    }

    s->modules[s->module_count++] = m;
    s->active_module              = m;

    return m;
}

void
n00b_cg_module_mark_private_func(n00b_cg_module_t *m, const char *name)
{
    if (!m || !name) {
        return;
    }

    if (n00b_cg_module_func_is_private(m, name)) {
        return;
    }

    if (m->private_func_count >= m->private_func_cap) {
        int32_t      new_cap   = m->private_func_cap ? m->private_func_cap * 2 : 8;
        const char **new_names = n00b_alloc_array(const char *, (size_t)new_cap);

        if (m->private_func_names) {
            memcpy(new_names,
                   m->private_func_names,
                   sizeof(const char *) * (size_t)m->private_func_count);
        }

        m->private_func_names = new_names;
        m->private_func_cap   = new_cap;
    }

    size_t len = strlen(name);
    char  *buf = n00b_alloc_array(char, len + 1);
    memcpy(buf, name, len + 1);
    m->private_func_names[m->private_func_count++] = buf;

    n00b_cg_session_t *s = m->session;

    if (!s || !s->private_func_index) {
        return;
    }

    bool                          found = false;
    n00b_cg_private_func_index_t *index
        = n00b_dict_untyped_get(s->private_func_index, buf, &found);

    if (!found || !index) {
        index = n00b_alloc(n00b_cg_private_func_index_t);
        n00b_dict_untyped_put(s->private_func_index, buf, index);
    }

    if (index->count >= index->cap) {
        int32_t            new_cap     = index->cap ? index->cap * 2 : 4;
        n00b_cg_module_t **new_modules = n00b_alloc_array(n00b_cg_module_t *, (size_t)new_cap);

        if (index->modules) {
            memcpy(new_modules,
                   index->modules,
                   sizeof(n00b_cg_module_t *) * (size_t)index->count);
        }

        index->modules = new_modules;
        index->cap     = new_cap;
    }

    index->modules[index->count++] = m;
}

bool
n00b_cg_module_func_is_private(n00b_cg_module_t *m, const char *name)
{
    if (!m || !name) {
        return false;
    }

    for (int32_t i = 0; i < m->private_func_count; i++) {
        if (m->private_func_names[i] && strcmp(m->private_func_names[i], name) == 0) {
            return true;
        }
    }

    return false;
}

bool
n00b_cg_func_is_private_in_other_module(n00b_cg_session_t *s, const char *name)
{
    if (!s || !name || !s->private_func_index) {
        return false;
    }

    bool                          found = false;
    n00b_cg_private_func_index_t *index
        = n00b_dict_untyped_get(s->private_func_index, name, &found);

    if (!found || !index) {
        return false;
    }

    n00b_cg_module_t *active = s->active_module;

    for (int32_t i = 0; i < index->count; i++) {
        if (index->modules[i] && index->modules[i] != active) {
            return true;
        }
    }

    return false;
}

static void *
n00b_cg_module_compile_traced(n00b_cg_module_t *m, const char *entry_func, FILE *code_trace)
{
    if (!m || !m->session) {
        return NULL;
    }

    n00b_cg_session_t *s = m->session;

    // Finish module if still building.
    if (m->state == N00B_CG_MOD_BUILDING) {
        MIR_finish_module(s->mir_ctx);
        m->state = N00B_CG_MOD_FINISHED;
    }

    codegen_resolve_runtime_callbacks(s);
    codegen_report_unresolved_runtime_callbacks(s);

    if (s->has_codegen_errors) {
        return NULL;
    }

    // Load module.
    if (m->state == N00B_CG_MOD_FINISHED) {
        MIR_load_module(s->mir_ctx, m->mir_module);

        // Resolve per-module imports.
        for (int32_t i = 0; i < m->import_count; i++) {
            MIR_load_external(s->mir_ctx, m->imports[i].name, m->imports[i].addr);
        }

        // Resolve session-level FFI imports.
        if (s->import_table) {
            for (int32_t i = 0; i < s->import_table->count; i++) {
                n00b_cg_import_entry_t *e = &s->import_table->entries[i];

                if (e->name && e->addr) {
                    MIR_load_external(s->mir_ctx, e->name, e->addr);
                }
            }
        }

        // Initialize generator if needed.
        if (!s->gen_inited) {
            MIR_gen_init(s->mir_ctx);
            s->gen_inited = true;
        }

        n00b_mir_enable_code_len_trace(s->mir_ctx, code_trace);
        MIR_link(s->mir_ctx, MIR_set_gen_interface, NULL);
        m->state = N00B_CG_MOD_LINKED;
    }

    if (!entry_func) {
        m->state = N00B_CG_MOD_COMPILED;
        return NULL;
    }

    // Find the entry function in this module.
    MIR_item_t func = NULL;

    MIR_item_t item;
    for (item = DLIST_HEAD(MIR_item_t, m->mir_module->items); item != NULL;
         item = DLIST_NEXT(MIR_item_t, item)) {
        if (item->item_type == MIR_func_item && strcmp(item->u.func->name, entry_func) == 0) {
            func = item;
            break;
        }
    }

    if (!func) {
        return NULL;
    }

    void *code = MIR_gen(s->mir_ctx, func);
    m->state   = N00B_CG_MOD_COMPILED;

    return code;
}

void *
n00b_cg_module_compile(n00b_cg_module_t *m, const char *entry_func)
{
    return n00b_cg_module_compile_traced(m, entry_func, NULL);
}

void
n00b_cg_set_active_module(n00b_cg_session_t *s, n00b_cg_module_t *m)
{
    s->active_module = m;
}

void
n00b_cg_module_set_annot(n00b_cg_module_t *m, n00b_annot_result_t *annot)
{
    m->annot = annot;
}

// ============================================================================
// Handler registration
// ============================================================================

bool
n00b_codegen_register(n00b_cg_session_t *s, const char *nt_name, n00b_cg_handler_fn handler)
{
    if (!s->grammar) {
        return false;
    }

    n00b_string_t *name = n00b_string_from_cstr(nt_name);
    bool           found;
    int64_t        id = n00b_dict_get(s->grammar->nt_map, name, &found);

    if (!found) {
        return false;
    }

    return n00b_codegen_register_by_id(s, id, handler);
}

bool
n00b_codegen_register_by_id(n00b_cg_session_t *s, int64_t nt_id, n00b_cg_handler_fn handler)
{
    if (!s->handlers || nt_id < 0 || nt_id >= s->handler_cap) {
        return false;
    }

    s->handlers[nt_id] = handler;
    return true;
}

void
n00b_codegen_map_operator(n00b_cg_session_t    *s,
                          const char           *token_text,
                          n00b_cg_semantic_op_t op)
{
    for (int32_t i = 0; i < s->op_map_count; i++) {
        if (strcmp(s->op_map[i].text, token_text) == 0) {
            s->op_map[i].op = op;
            return;
        }
    }

    if (s->op_map_count >= s->op_map_cap) {
        int32_t             new_cap = s->op_map_cap * 2;
        n00b_cg_op_entry_t *new_map = n00b_alloc_array(n00b_cg_op_entry_t, (size_t)new_cap);
        memcpy(new_map, s->op_map, sizeof(n00b_cg_op_entry_t) * (size_t)s->op_map_count);
        s->op_map     = new_map;
        s->op_map_cap = new_cap;
    }

    s->op_map[s->op_map_count++] = (n00b_cg_op_entry_t){
        .text = token_text,
        .op   = op,
    };
}

// ============================================================================
// Queries
// ============================================================================

/**
 * @brief Get the current annotation result.
 *
 * Checks active module first, then session-level (backward compat).
 */
static inline n00b_annot_result_t *
current_annot(n00b_cg_session_t *s)
{
    if (s->active_module && s->active_module->annot) {
        return s->active_module->annot;
    }

    return s->annot;
}

static n00b_tc_type_t *
lookup_node_type(n00b_annot_result_t *a, n00b_parse_tree_t *node)
{
    if (!a || !a->node_types || !node) {
        return NULL;
    }

    bool            found = false;
    uintptr_t       key   = (uintptr_t)node;
    n00b_tc_type_t *type  = n00b_dict_get(a->node_types, key, &found);

    if (found && type) {
        return type;
    }

    // A moving GC can update pointer-like keys after the dict has been
    // bucketed. Fall back to a linear scan before treating a node as untyped.
    n00b_dict_foreach(a->node_types, stored_key, stored_type, {
        if (stored_key == key) {
            type  = stored_type;
            found = true;
            break;
        }
    });

    return found ? type : NULL;
}

n00b_cg_type_tag_t
n00b_codegen_node_type(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    n00b_annot_result_t *a    = current_annot(s);
    n00b_tc_type_t      *type = lookup_node_type(a, node);

    if (!type) {
        return N00B_CG_I64;
    }

    if (s->type_map) {
        return s->type_map(s, type);
    }

    return N00B_CG_I64;
}

n00b_tc_type_t *
n00b_codegen_node_tc_type(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    n00b_annot_result_t *a    = current_annot(s);
    n00b_tc_type_t      *type = lookup_node_type(a, node);

    if (!type) {
        return NULL;
    }

    return n00b_tc_find(type);
}

n00b_cf_label_t *
n00b_codegen_cf_label(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    n00b_annot_result_t *a = current_annot(s);

    if (!a) {
        return NULL;
    }

    n00b_cf_label_t *label = n00b_cf_label_lookup(a->cf_labels, node);

    if (label || !a->cf_labels || !node) {
        return label;
    }

    // See lookup_node_type(): after GC relocation, pointer-key dictionaries
    // may contain updated keys in old buckets. Iteration still sees them.
    n00b_dict_foreach(a->cf_labels, stored_node, stored_label, {
        if (stored_node == node || (stored_label && stored_label->self == node)) {
            label = stored_label;
            break;
        }
    });

    return label;
}

n00b_grammar_t *
n00b_codegen_grammar(n00b_cg_session_t *s)
{
    return s->grammar;
}

n00b_annot_result_t *
n00b_codegen_annot(n00b_cg_session_t *s)
{
    return current_annot(s);
}

n00b_annot_result_t *
n00b_codegen_set_annot(n00b_cg_session_t *s, n00b_annot_result_t *annot)
{
    n00b_annot_result_t *prev = s->annot;
    s->annot                  = annot;
    return prev;
}

n00b_diag_ctx_t *
n00b_codegen_diagnostics(n00b_cg_session_t *s)
{
    return s->diag;
}

void *
n00b_codegen_get_user_data(n00b_cg_session_t *s)
{
    return s->user_data;
}

// Emit a codegen-stage diagnostic.
// Uses n00b_diag_push which allocates strings. When calling during
// the codegen tree walk, the GC allocation can trigger conduit crashes
// (known infrastructure issue). For now, we also set the diag error
// count directly as a fallback.
static void
codegen_error(n00b_cg_session_t *s, n00b_parse_tree_t *node, const char *code, const char *msg)
{
    n00b_diag_span_t span = n00b_diag_span_from_node(node);

    fprintf(stderr, "error[%s]: %s", code, msg);

    if (span.start_line > 0) {
        fprintf(stderr, " (line %u, col %u)", span.start_line, span.start_col);
    }

    fprintf(stderr, "\n");

    if (s->diag) {
        s->diag->error_count++;
    }

    s->has_codegen_errors = true;
}

static n00b_cg_val_t
codegen_use_stmt(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    (void)s;
    (void)node;
    return N00B_CG_VOID_VAL;
}

static n00b_cg_val_t
codegen_yield_stmt(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    if (s->reject_unconsumed_yield) {
        codegen_error(s, node, "CG022", "yield value is not consumed in this context");
        return N00B_CG_VOID_VAL;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (child && !n00b_pt_is_token(child) && n00b_pt_is_nt(child, "expression")) {
            return codegen_walk(s, child);
        }
    }

    return N00B_CG_VOID_VAL;
}

static bool
codegen_tree_contains_nt(n00b_parse_tree_t *node, const char *nt_name)
{
    if (!node || !nt_name || n00b_pt_is_token(node)) {
        return false;
    }

    if (n00b_pt_is_nt(node, nt_name)) {
        return true;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        if (codegen_tree_contains_nt(n00b_pt_get_child(node, i), nt_name)) {
            return true;
        }
    }

    return false;
}

static bool
codegen_token_text_matches(n00b_parse_tree_t *node, const char *text)
{
    if (!node || !text || !n00b_pt_is_token(node)) {
        return false;
    }

    size_t      expected = strlen(text);
    const char *actual   = n00b_pt_token_text(node);
    size_t      len      = n00b_pt_token_text_len(node);

    return actual && len == expected && memcmp(actual, text, expected) == 0;
}

static bool
codegen_text_is_punctuation(const char *text, size_t len)
{
    return len == 1 && (text[0] == ':' || text[0] == ',' || text[0] == '.');
}

static char *
codegen_dup_raw_text(const char *text, size_t len)
{
    if (!text) {
        return NULL;
    }

    char *result = n00b_alloc_array(char, len + 1);
    memcpy(result, text, len);
    result[len] = '\0';
    return result;
}

static const char *
codegen_current_function_name(n00b_cg_session_t *s)
{
    n00b_cg_module_t *m = s ? s->active_module : NULL;

    if (!m || !m->cur_func || !m->cur_func->u.func) {
        return NULL;
    }

    return m->cur_func->u.func->name;
}

static char *
codegen_join_key3(const char *first, const char *second, const char *third)
{
    if (!first || !second || !third) {
        return NULL;
    }

    size_t first_len  = strlen(first);
    size_t second_len = strlen(second);
    size_t third_len  = strlen(third);
    char  *key        = n00b_alloc_array(char, first_len + second_len + third_len + 3);

    memcpy(key, first, first_len);
    key[first_len] = ':';
    memcpy(key + first_len + 1, second, second_len);
    key[first_len + second_len + 1] = ':';
    memcpy(key + first_len + second_len + 2, third, third_len);
    key[first_len + second_len + third_len + 2] = '\0';
    return key;
}

static char *
codegen_join_key2(const char *first, const char *second)
{
    if (!first || !second) {
        return NULL;
    }

    size_t first_len  = strlen(first);
    size_t second_len = strlen(second);
    char  *key        = n00b_alloc_array(char, first_len + second_len + 2);

    memcpy(key, first, first_len);
    key[first_len] = ':';
    memcpy(key + first_len + 1, second, second_len);
    key[first_len + second_len + 1] = '\0';
    return key;
}

static char *
codegen_module_key2(n00b_cg_module_t *module, const char *second)
{
    if (!module || !second) {
        return NULL;
    }

    char mod_buf[32];
    snprintf(mod_buf, sizeof(mod_buf), "%p", (void *)module);
    return codegen_join_key2(mod_buf, second);
}

static char *
codegen_module_key3(n00b_cg_module_t *module, const char *second, const char *third)
{
    if (!module || !second || !third) {
        return NULL;
    }

    char mod_buf[32];
    snprintf(mod_buf, sizeof(mod_buf), "%p", (void *)module);
    return codegen_join_key3(mod_buf, second, third);
}

static char *
codegen_local_type_key(n00b_cg_session_t *s, const char *name)
{
    n00b_cg_module_t *m         = s ? s->active_module : NULL;
    const char       *func_name = codegen_current_function_name(s);

    if (!m || !func_name || !name) {
        return NULL;
    }

    return codegen_module_key3(m, func_name, name);
}

static void
codegen_store_local_type(n00b_cg_session_t *s, const char *name, n00b_cg_type_tag_t tag)
{
    if (!s || !s->local_types || !name) {
        return;
    }

    char *key = codegen_local_type_key(s, name);

    if (!key) {
        return;
    }

    n00b_dict_untyped_put(s->local_types, key, (void *)(uintptr_t)((uint64_t)tag + 1));
}

static bool
codegen_lookup_local_type(n00b_cg_session_t *s, const char *name, n00b_cg_type_tag_t *tag)
{
    if (!s || !s->local_types || !name || !tag) {
        return false;
    }

    char *key = codegen_local_type_key(s, name);

    if (!key) {
        return false;
    }

    bool  found = false;
    void *value = n00b_dict_untyped_get(s->local_types, key, &found);

    if (!found || !value) {
        return false;
    }

    *tag = (n00b_cg_type_tag_t)((uintptr_t)value - 1);
    return true;
}

static void
codegen_store_local_callback(n00b_cg_session_t *s, const char *name, n00b_rt_callback_t *cb)
{
    if (!s || !s->local_callbacks || !name || !cb) {
        return;
    }

    char *key = codegen_local_type_key(s, name);

    if (!key) {
        return;
    }

    n00b_dict_untyped_put(s->local_callbacks, key, cb);
}

static n00b_rt_callback_t *
codegen_lookup_local_callback(n00b_cg_session_t *s, const char *name)
{
    if (!s || !s->local_callbacks || !name) {
        return NULL;
    }

    char *key = codegen_local_type_key(s, name);

    if (!key) {
        return NULL;
    }

    bool  found = false;
    void *value = n00b_dict_untyped_get(s->local_callbacks, key, &found);

    return found ? (n00b_rt_callback_t *)value : NULL;
}

typedef struct {
    MIR_context_t mir_ctx;
    MIR_item_t    target_func;
} n00b_cg_mir_callback_target_t;

static bool
codegen_mir_callback_invoke(void *target, MIR_val_t *result, MIR_val_t *args, int32_t n_args)
{
    n00b_cg_mir_callback_target_t *mir_target = (n00b_cg_mir_callback_target_t *)target;

    if (!mir_target || !mir_target->mir_ctx || !mir_target->target_func || !result) {
        return false;
    }

    if (n_args > 0 && args) {
        MIR_interp_arr(mir_target->mir_ctx,
                       mir_target->target_func,
                       result,
                       (size_t)n_args,
                       args);
    }
    else {
        MIR_interp(mir_target->mir_ctx, mir_target->target_func, result, 0);
    }

    return true;
}

static n00b_cg_mir_callback_target_t *
codegen_mir_callback_target(n00b_rt_callback_t *cb)
{
    if (!cb) {
        return NULL;
    }

    if (!cb->target) {
        cb->target = n00b_alloc(n00b_cg_mir_callback_target_t);
    }

    cb->invoke = codegen_mir_callback_invoke;
    return (n00b_cg_mir_callback_target_t *)cb->target;
}

static bool
codegen_callback_has_target(n00b_rt_callback_t *cb)
{
    return cb && cb->target && cb->invoke;
}

static void
codegen_resolve_runtime_callback(n00b_cg_session_t  *s,
                                 n00b_rt_callback_t *cb,
                                 n00b_cg_module_t   *module)
{
    if (!s || !cb) {
        return;
    }

    if (cb->func_name) {
        n00b_cg_module_t *saved_active = s->active_module;

        if (module) {
            s->active_module = module;
        }

        MIR_item_t target = n00b_cg_find_func(s, cb->func_name);

        s->active_module = saved_active;

        if (target) {
            n00b_cg_mir_callback_target_t *mir_target = codegen_mir_callback_target(cb);

            if (mir_target) {
                mir_target->mir_ctx     = s->mir_ctx;
                mir_target->target_func = target;
            }
        }
    }
}

static void
codegen_register_runtime_callback(n00b_cg_session_t  *s,
                                  n00b_rt_callback_t *cb,
                                  n00b_parse_tree_t  *site)
{
    if (!s || !cb) {
        return;
    }

    codegen_resolve_runtime_callback(s, cb, s->active_module);

    if (s->runtime_callback_count >= s->runtime_callback_cap) {
        int32_t new_cap = s->runtime_callback_cap ? s->runtime_callback_cap * 2 : 8;
        n00b_cg_runtime_callback_ref_t *new_callbacks
            = n00b_alloc_array(n00b_cg_runtime_callback_ref_t, (size_t)new_cap);

        for (int32_t i = 0; i < s->runtime_callback_count; i++) {
            new_callbacks[i] = s->runtime_callbacks[i];
        }

        s->runtime_callbacks    = new_callbacks;
        s->runtime_callback_cap = new_cap;
    }

    s->runtime_callbacks[s->runtime_callback_count++] = (n00b_cg_runtime_callback_ref_t){
        .callback            = cb,
        .module              = s->active_module,
        .site                = site,
        .reported_unresolved = false,
    };
}

static void
codegen_resolve_runtime_callbacks(n00b_cg_session_t *s)
{
    if (!s) {
        return;
    }

    for (int32_t i = 0; i < s->runtime_callback_count; i++) {
        codegen_resolve_runtime_callback(s,
                                         s->runtime_callbacks[i].callback,
                                         s->runtime_callbacks[i].module);
    }
}

static void
codegen_report_unresolved_callback(n00b_cg_session_t *s, n00b_cg_runtime_callback_ref_t *ref)
{
    if (!s || !ref || ref->reported_unresolved) {
        return;
    }

    n00b_rt_callback_t *cb = ref->callback;

    if (!cb || codegen_callback_has_target(cb) || !cb->func_name) {
        return;
    }

    if (ref->module && ref->module->state == N00B_CG_MOD_BUILDING) {
        return;
    }

    codegen_error(s,
                  ref->site,
                  "CG009",
                  n00b_unicode_str_to_cstr(
                      n00b_cformat("callback target '[|#|]' is not defined",
                                   n00b_string_from_cstr(cb->func_name))));
    ref->reported_unresolved = true;
}

static void
codegen_report_unresolved_runtime_callbacks(n00b_cg_session_t *s)
{
    if (!s) {
        return;
    }

    for (int32_t i = 0; i < s->runtime_callback_count; i++) {
        codegen_report_unresolved_callback(s, &s->runtime_callbacks[i]);
    }
}

static n00b_cg_type_tag_t
codegen_type_tag_from_mir_type(MIR_type_t type)
{
    switch (type) {
    case MIR_T_F:
        return N00B_CG_F32;
    case MIR_T_D:
        return N00B_CG_F64;
    case MIR_T_I8:
        return N00B_CG_I8;
    case MIR_T_I16:
        return N00B_CG_I16;
    case MIR_T_I32:
        return N00B_CG_I32;
    case MIR_T_U8:
        return N00B_CG_U8;
    case MIR_T_U16:
        return N00B_CG_U16;
    case MIR_T_U32:
        return N00B_CG_U32;
    case MIR_T_U64:
        return N00B_CG_U64;
    default:
        return N00B_CG_I64;
    }
}

static bool
codegen_lookup_param_mir_type(MIR_func_t func, const char *name, n00b_cg_type_tag_t *tag)
{
    if (!func || !name || !tag) {
        return false;
    }

    for (uint32_t i = 0; i < func->nargs; i++) {
        MIR_var_t var = VARR_GET(MIR_var_t, func->vars, i);

        if (var.name && strcmp(var.name, name) == 0) {
            *tag = codegen_type_tag_from_mir_type(var.type);
            return true;
        }
    }

    return false;
}

static void
codegen_store_local_layout(n00b_cg_session_t *s, const char *name, n00b_class_layout_t *layout)
{
    if (!s || !s->local_layouts || !name || !layout) {
        return;
    }

    char *key = codegen_local_type_key(s, name);

    if (!key) {
        return;
    }

    n00b_dict_untyped_put(s->local_layouts, key, layout);
}

static n00b_class_layout_t *
codegen_lookup_local_layout(n00b_cg_session_t *s, const char *name)
{
    if (!s || !s->local_layouts || !name) {
        return NULL;
    }

    char *key = codegen_local_type_key(s, name);

    if (!key) {
        return NULL;
    }

    bool  found = false;
    void *value = n00b_dict_untyped_get(s->local_layouts, key, &found);

    return found ? (n00b_class_layout_t *)value : NULL;
}

static n00b_parse_tree_t *
codegen_find_nt_local(n00b_parse_tree_t *node, const char *nt_name)
{
    if (!node || !nt_name || n00b_pt_is_token(node)) {
        return NULL;
    }

    if (n00b_pt_is_nt(node, nt_name)) {
        return node;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *found = codegen_find_nt_local(n00b_pt_get_child(node, i), nt_name);

        if (found) {
            return found;
        }
    }

    return NULL;
}

static int32_t
codegen_count_nt_local(n00b_parse_tree_t *node, const char *nt_name)
{
    if (!node || !nt_name || n00b_pt_is_token(node)) {
        return 0;
    }

    int32_t count = n00b_pt_is_nt(node, nt_name) ? 1 : 0;
    size_t  nc    = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        count += codegen_count_nt_local(n00b_pt_get_child(node, i), nt_name);
    }

    return count;
}

static int32_t
codegen_collect_nt_local(n00b_parse_tree_t  *node,
                         const char         *nt_name,
                         n00b_parse_tree_t **out,
                         int32_t             max)
{
    if (!node || !nt_name || !out || max <= 0 || n00b_pt_is_token(node)) {
        return 0;
    }

    int32_t count = 0;

    if (n00b_pt_is_nt(node, nt_name)) {
        out[count++] = node;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc && count < max; i++) {
        count += codegen_collect_nt_local(n00b_pt_get_child(node, i),
                                          nt_name,
                                          out + count,
                                          max - count);
    }

    return count;
}

static void
codegen_collect_tokens_local(n00b_parse_tree_t  *node,
                             n00b_parse_tree_t **out,
                             int32_t             max,
                             int32_t            *count)
{
    if (!node || !out || !count || *count >= max) {
        return;
    }

    if (n00b_pt_is_token(node)) {
        out[(*count)++] = node;
        return;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc && *count < max; i++) {
        codegen_collect_tokens_local(n00b_pt_get_child(node, i), out, max, count);
    }
}

static char *
codegen_parameter_local_name(n00b_parse_tree_t *node)
{
    n00b_parse_tree_t *target = codegen_find_nt_local(node, "param-target");

    if (!target) {
        return NULL;
    }

    n00b_parse_tree_t *tokens[16];
    int32_t            ntokens = 0;

    codegen_collect_tokens_local(target, tokens, 16, &ntokens);

    for (int32_t i = 0; i + 1 < ntokens; i++) {
        if (!codegen_token_text_matches(tokens[i], "var")) {
            continue;
        }

        for (int32_t j = i + 1; j < ntokens; j++) {
            const char *text = n00b_pt_token_text(tokens[j]);
            size_t      len  = n00b_pt_token_text_len(tokens[j]);

            if (text && len > 0 && !codegen_text_is_punctuation(text, len)) {
                return codegen_dup_raw_text(text, len);
            }
        }
    }

    return NULL;
}

static n00b_string_t *
codegen_parameter_display_name(n00b_parse_tree_t *node, const char *fallback)
{
    n00b_parse_tree_t *target = codegen_find_nt_local(node, "param-target");

    if (!target) {
        return n00b_string_from_cstr(fallback ? fallback : "parameter");
    }

    n00b_parse_tree_t *tokens[32];
    int32_t            ntokens = 0;
    char               buf[256];
    size_t             used = 0;

    codegen_collect_tokens_local(target, tokens, 32, &ntokens);

    for (int32_t i = 0; i < ntokens; i++) {
        const char *text = n00b_pt_token_text(tokens[i]);
        size_t      len  = n00b_pt_token_text_len(tokens[i]);

        if (!text || len == 0 || codegen_token_text_matches(tokens[i], "var")) {
            continue;
        }

        if (used + len >= sizeof(buf)) {
            break;
        }

        memcpy(buf + used, text, len);
        used += len;
    }

    if (used == 0) {
        return n00b_string_from_cstr(fallback ? fallback : "parameter");
    }

    return n00b_string_from_raw(buf, (int64_t)used);
}

static char *
codegen_callback_function_name(n00b_parse_tree_t *callback)
{
    if (!callback) {
        return NULL;
    }

    n00b_parse_tree_t *tokens[16];
    int32_t            ntokens = 0;

    codegen_collect_tokens_local(callback, tokens, 16, &ntokens);

    for (int32_t i = 0; i + 1 < ntokens; i++) {
        if (!codegen_token_text_matches(tokens[i], "func")) {
            continue;
        }

        const char *text = n00b_pt_token_text(tokens[i + 1]);
        size_t      len  = n00b_pt_token_text_len(tokens[i + 1]);

        if (text && len > 0) {
            return codegen_dup_raw_text(text, len);
        }
    }

    return NULL;
}

static void
codegen_parameter_prop(n00b_parse_tree_t  *prop,
                       n00b_parse_tree_t **default_expr,
                       char              **callback_name,
                       char              **validator_name)
{
    if (!prop) {
        return;
    }

    n00b_parse_tree_t *first = n00b_pt_first_token(prop);

    if (codegen_token_text_matches(first, "default")) {
        *default_expr = codegen_find_nt_local(prop, "expression");
        return;
    }

    if (codegen_token_text_matches(first, "callback")) {
        n00b_parse_tree_t *cb = codegen_find_nt_local(prop, "callback-lit");
        *callback_name        = codegen_callback_function_name(cb);
        return;
    }

    if (codegen_token_text_matches(first, "validator")) {
        n00b_parse_tree_t *cb = codegen_find_nt_local(prop, "callback-lit");
        *validator_name       = codegen_callback_function_name(cb);
        return;
    }
}

static void
codegen_collect_parameter_props(n00b_parse_tree_t  *node,
                                n00b_parse_tree_t **out,
                                int32_t             max,
                                int32_t            *count)
{
    if (!node || !out || !count || *count >= max || n00b_pt_is_token(node)) {
        return;
    }

    if (n00b_pt_is_nt(node, "param-prop")) {
        out[(*count)++] = node;
        return;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc && *count < max; i++) {
        codegen_collect_parameter_props(n00b_pt_get_child(node, i), out, max, count);
    }
}

static n00b_cg_val_t
codegen_parameter_block(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    char *local_name = codegen_parameter_local_name(node);

    n00b_parse_tree_t *props[16];
    int32_t            nprops         = 0;
    n00b_parse_tree_t *default_expr   = NULL;
    char              *callback_name  = NULL;
    char              *validator_name = NULL;

    codegen_collect_parameter_props(node, props, 16, &nprops);

    for (int32_t i = 0; i < nprops; i++) {
        codegen_parameter_prop(props[i], &default_expr, &callback_name, &validator_name);
    }

    n00b_cg_val_t value = N00B_CG_VOID_VAL;

    if (default_expr) {
        value = codegen_walk(s, default_expr);
    }
    else if (callback_name) {
        if (codegen_reject_private_cross_module_call(s, node, callback_name)) {
            return N00B_CG_VOID_VAL;
        }

        if (!n00b_cg_find_import(s, callback_name) && !n00b_cg_find_func(s, callback_name)) {
            codegen_error(s,
                          node,
                          "CG009",
                          n00b_unicode_str_to_cstr(
                              n00b_cformat("callback target '[|#|]' is not defined",
                                           n00b_string_from_cstr(callback_name))));
            return N00B_CG_VOID_VAL;
        }

        n00b_cg_type_tag_t ret_type
            = codegen_lookup_func_ret_type(s, callback_name, N00B_CG_I64);
        value = n00b_cg_emit_call(s, callback_name, NULL, 0, .ret = ret_type);
    }

    if (value.kind == N00B_CG_VAL_VOID) {
        return N00B_CG_VOID_VAL;
    }

    if (validator_name) {
        n00b_cg_val_t ok = n00b_cg_emit_call(s, validator_name, &value, 1, .ret = N00B_CG_I64);
        n00b_cg_type_tag_t pt[] = {N00B_CG_I64, N00B_CG_I64};
        n00b_cg_import_func(s,
                            "n00b_builtin_parameter_validate",
                            (void *)n00b_builtin_parameter_validate,
                            .ret         = N00B_CG_VOID,
                            .param_types = pt,
                            .n_params    = 2);
        n00b_string_t *name     = codegen_parameter_display_name(node, local_name);
        n00b_cg_val_t  name_arg = (n00b_cg_val_t){
             .kind     = N00B_CG_VAL_IMM,
             .type_tag = N00B_CG_STRING,
             .aux      = (uint64_t)(uintptr_t)name,
        };
        n00b_cg_val_t args[] = {name_arg, ok};
        n00b_cg_emit_call(s, "n00b_builtin_parameter_validate", args, 2, .ret = N00B_CG_VOID);
    }

    if (!local_name) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_val_t dst = n00b_cg_local(s, local_name, .type = value.type_tag);
    codegen_store_local_type(s, local_name, value.type_tag);
    n00b_cg_store(s, dst, value);
    return dst;
}

static uint64_t
codegen_hash_key_bytes(uint64_t hash, const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;

    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }

    return hash;
}

static uint64_t
codegen_once_key_value(n00b_cg_session_t *s, const char *func_name)
{
    uint64_t          hash = n00b_codegen_session_namespace_key(s);
    n00b_cg_module_t *m    = s ? s->active_module : NULL;
    uint64_t          mod  = (uint64_t)(uintptr_t)m;

    hash = codegen_hash_key_bytes(hash, &mod, sizeof(mod));

    if (func_name) {
        hash = codegen_hash_key_bytes(hash, func_name, strlen(func_name));
    }

    return hash ? hash : 1;
}

static n00b_cg_val_t
codegen_confspec_block(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    int64_t sections = codegen_count_nt_local(node, "section-type");
    int64_t fields   = codegen_count_nt_local(node, "field-spec");

    n00b_cg_type_tag_t pt[] = {N00B_CG_I64, N00B_CG_I64, N00B_CG_I64};
    n00b_cg_import_func(s,
                        "n00b_builtin_confspec_register",
                        (void *)n00b_builtin_confspec_register,
                        .ret         = N00B_CG_VOID,
                        .param_types = pt,
                        .n_params    = 3);

    n00b_cg_val_t args[] = {
        _n00b_cg_const_i64(s, (int64_t)n00b_codegen_session_namespace_key(s)),
        _n00b_cg_const_i64(s, sections),
        _n00b_cg_const_i64(s, fields),
    };
    n00b_cg_emit_call(s, "n00b_builtin_confspec_register", args, 3, .ret = N00B_CG_VOID);

    return N00B_CG_VOID_VAL;
}

static n00b_cg_val_t
codegen_interface_decl(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    (void)s;
    (void)node;
    return N00B_CG_VOID_VAL;
}

static n00b_cg_val_t
codegen_callback_lit(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    char *func_name = codegen_callback_function_name(node);

    if (!func_name) {
        codegen_error(s, node, "CG009", "callback literal is missing a target function");
        return N00B_CG_VOID_VAL;
    }

    n00b_rt_callback_t *cb = n00b_alloc(n00b_rt_callback_t);
    cb->func_name          = func_name;
    codegen_fill_callback_signature(s, func_name, cb);
    codegen_register_runtime_callback(s, cb, node);

    return (n00b_cg_val_t){
        .kind     = N00B_CG_VAL_IMM,
        .type_tag = N00B_CG_FUNC,
        .aux      = (uint64_t)(uintptr_t)cb,
    };
}

static n00b_cg_val_t
codegen_extern_block(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    n00b_cg_module_t *m = s ? s->active_module : NULL;

    if (!m || m->cur_func != NULL) {
        return N00B_CG_VOID_VAL;
    }

    n00b_parse_tree_t *name_tok   = NULL;
    n00b_parse_tree_t *sig_node   = NULL;
    n00b_parse_tree_t *body_node  = NULL;
    bool               saw_extern = false;
    size_t             nc         = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (!child) {
            continue;
        }

        if (n00b_pt_is_token(child)) {
            if (codegen_token_text_matches(child, "extern")) {
                saw_extern = true;
                continue;
            }

            if (saw_extern && !name_tok) {
                name_tok = child;
            }

            continue;
        }

        if (n00b_pt_is_nt(child, "extern-signature")) {
            sig_node = child;
        }
        else if (n00b_pt_is_nt(child, "extern-body")) {
            body_node = child;
        }
    }

    if (body_node && codegen_find_nt_local(body_node, "extern-stmts")) {
        codegen_error(s, node, "CG019", "extern body clauses are not supported");
        return N00B_CG_VOID_VAL;
    }

    n00b_parse_tree_t *type_nodes[33];
    int                n_types
        = sig_node ? codegen_collect_nt_local(sig_node, "extern-type-id", type_nodes, 33) : 0;

    if (!name_tok || n_types < 1) {
        codegen_error(s, node, "CG019", "extern declaration could not be lowered");
        return N00B_CG_VOID_VAL;
    }

    char *name
        = codegen_dup_raw_text(n00b_pt_token_text(name_tok), n00b_pt_token_text_len(name_tok));
    const char *param_types[32];
    int32_t     n_params = n_types - 1;

    if (n_params > 32) {
        codegen_error(s, node, "CG019", "extern declaration has too many parameters");
        return N00B_CG_VOID_VAL;
    }

    for (int32_t i = 0; i < n_params; i++) {
        n00b_parse_tree_t *tok = n00b_pt_first_token(type_nodes[i]);
        param_types[i]
            = tok ? codegen_dup_raw_text(n00b_pt_token_text(tok), n00b_pt_token_text_len(tok))
                  : NULL;

        if (!param_types[i]) {
            codegen_error(s, type_nodes[i], "CG019", "extern parameter type is missing");
            return N00B_CG_VOID_VAL;
        }
    }

    n00b_parse_tree_t *ret_tok = n00b_pt_first_token(type_nodes[n_types - 1]);
    char              *ret     = ret_tok ? codegen_dup_raw_text(n00b_pt_token_text(ret_tok),
                                               n00b_pt_token_text_len(ret_tok))
                                         : NULL;

    if (!name || !ret) {
        codegen_error(s, node, "CG019", "extern declaration could not be lowered");
        return N00B_CG_VOID_VAL;
    }

    if (!n00b_ffi_install_simple(s, name, name, param_types, n_params, ret)) {
        codegen_error(s, node, "CG019", "extern declaration could not be installed");
    }

    return N00B_CG_VOID_VAL;
}

static n00b_parse_tree_t *
codegen_find_nt_deep(n00b_parse_tree_t *node, const char *nt_name)
{
    if (!node || n00b_pt_is_token(node)) {
        return NULL;
    }

    if (n00b_pt_is_nt(node, nt_name)) {
        return node;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *found = codegen_find_nt_deep(n00b_pt_get_child(node, i), nt_name);

        if (found) {
            return found;
        }
    }

    return NULL;
}

static bool
codegen_token_text_is(n00b_parse_tree_t *tok, const char *name)
{
    if (!tok || !name) {
        return false;
    }

    const char *text = n00b_pt_token_text(tok);
    size_t      len  = n00b_pt_token_text_len(tok);
    size_t      nlen = strlen(name);

    return text && len == nlen && memcmp(text, name, nlen) == 0;
}

static n00b_parse_tree_t *
codegen_type_constructor_token(n00b_parse_tree_t *node)
{
    n00b_parse_tree_t *member_chain = codegen_find_nt_deep(node, "member-chain");

    if (member_chain) {
        n00b_parse_tree_t *tok = n00b_pt_first_token(member_chain);

        if (tok) {
            return tok;
        }
    }

    return n00b_pt_first_token(node);
}

static n00b_cg_type_tag_t
codegen_decl_type_tag(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    n00b_cg_type_tag_t tag = n00b_codegen_node_type(s, node);
    n00b_parse_tree_t *tok = codegen_type_constructor_token(node);

    if (codegen_token_text_is(tok, "option") || codegen_token_text_is(tok, "maybe")) {
        return N00B_CG_OPTION;
    }

    if (codegen_token_text_is(tok, "result")) {
        return N00B_CG_RESULT;
    }

    if (codegen_token_text_is(tok, "list")) {
        return N00B_CG_LIST;
    }

    if (codegen_token_text_is(tok, "dict")) {
        return N00B_CG_DICT;
    }

    if (codegen_token_text_is(tok, "set")) {
        return N00B_CG_SET;
    }

    if (codegen_token_text_is(tok, "string")) {
        return N00B_CG_STRING;
    }

    if (codegen_token_text_is(tok, "i8")) {
        return N00B_CG_I8;
    }

    if (codegen_token_text_is(tok, "i16")) {
        return N00B_CG_I16;
    }

    if (codegen_token_text_is(tok, "i32")) {
        return N00B_CG_I32;
    }

    if (codegen_token_text_is(tok, "int") || codegen_token_text_is(tok, "i64")) {
        return N00B_CG_I64;
    }

    if (codegen_token_text_is(tok, "u8")) {
        return N00B_CG_U8;
    }

    if (codegen_token_text_is(tok, "u16")) {
        return N00B_CG_U16;
    }

    if (codegen_token_text_is(tok, "u32")) {
        return N00B_CG_U32;
    }

    if (codegen_token_text_is(tok, "u64")) {
        return N00B_CG_U64;
    }

    if (codegen_token_text_is(tok, "f32")) {
        return N00B_CG_F32;
    }

    if (codegen_token_text_is(tok, "float") || codegen_token_text_is(tok, "f64")) {
        return N00B_CG_F64;
    }

    if (codegen_token_text_is(tok, "bool")) {
        return N00B_CG_BOOL;
    }

    if (codegen_token_text_is(tok, "void")) {
        return N00B_CG_VOID;
    }

    return tag;
}

static bool
codegen_call_args_have_kwargs(n00b_parse_tree_t *args_node, n00b_parse_tree_t **kw_arg_out)
{
    n00b_parse_tree_t *kw_arg = codegen_find_nt_deep(args_node, "call-kw-arg");

    if (kw_arg) {
        if (kw_arg_out) {
            *kw_arg_out = kw_arg;
        }

        return true;
    }

    return false;
}

// ============================================================================
// Default literal parser (strtoll / strtod)
// ============================================================================

static n00b_cg_val_t
default_literal_parser(n00b_cg_session_t *s,
                       n00b_parse_tree_t *node,
                       n00b_string_t     *lit_kind,
                       n00b_cg_type_tag_t type_tag)
{
    const char *text = n00b_pt_token_text(node);
    size_t      len  = n00b_pt_token_text_len(node);

    if (!text || len == 0) {
        return _n00b_cg_const_i64(s, 0);
    }

    char *buf = n00b_alloc_array(char, len + 1);
    memcpy(buf, text, len);
    buf[len] = '\0';

    // Boolean literals.
    if (type_tag == N00B_CG_BOOL || (len == 4 && memcmp(text, "true", 4) == 0)
        || (len == 5 && memcmp(text, "false", 5) == 0)) {
        bool val = (len == 4 && memcmp(text, "true", 4) == 0);
        return _n00b_cg_const_bool(s, val);
    }

    // String literals: type is STRING (or legacy PTR), or text starts
    // with a quote char.
    if (type_tag == N00B_CG_STRING || type_tag == N00B_CG_PTR
        || (len >= 2 && (text[0] == '"' || text[0] == '\''))) {
        // Strip quotes if present.
        const char *str_data = buf;
        size_t      str_len  = len;

        if (str_len >= 2 && (str_data[0] == '"' || str_data[0] == '\'')) {
            str_data++;
            str_len -= 2;
        }

        // Create an n00b_string_t for the literal. The pointer is baked
        // into generated code as a raw immediate the GC cannot see, so
        // it MUST NOT live on the moving GC heap: a compaction would
        // relocate the object and leave the immediate dangling (the
        // crash a multi-fixture audit hit once a collection fired).
        // Allocate it (struct + .data) from the runtime `system_pool`,
        // which is non-arena, non-GC-scanned and never moved or freed —
        // the runtime analogue of the pinned static objects ncc emits
        // for AOT string literals.
        n00b_string_t *str_obj = n00b_string_from_raw(
            str_data,
            (int64_t)str_len,
            .allocator = n00b_system_allocator());

        return (n00b_cg_val_t){
            .kind     = N00B_CG_VAL_IMM,
            .type_tag = N00B_CG_STRING,
            .aux      = (uint64_t)(uintptr_t)str_obj,
        };
    }

    if (type_tag == N00B_CG_F64) {
        return _n00b_cg_const_f64(s, strtod(buf, NULL));
    }

    if (type_tag == N00B_CG_F32) {
        return _n00b_cg_const_f32(s, strtof(buf, NULL));
    }

    return _n00b_cg_const_i64(s, strtoll(buf, NULL, 0));
}

// ============================================================================
// Tree walk helpers (forward declarations)
// ============================================================================

static n00b_cg_val_t codegen_walk(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_operator(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t
codegen_literal(n00b_cg_session_t *s, n00b_parse_tree_t *node, n00b_annotation_t *annot);
static n00b_cg_val_t
codegen_call_auto(n00b_cg_session_t *s, n00b_parse_tree_t *node, n00b_annotation_t *annot);

typedef struct {
    n00b_parse_tree_t *container;
    n00b_parse_tree_t *start;
    n00b_parse_tree_t *end;
    bool               is_slice;
    bool               has_start;
    bool               has_end;
} codegen_index_info_t;

static n00b_cg_val_t codegen_branch(n00b_cg_session_t *s, n00b_cf_label_t *cf);
static n00b_cg_val_t codegen_loop(n00b_cg_session_t *s, n00b_cf_label_t *cf);
static n00b_cg_val_t codegen_jump(n00b_cg_session_t *s, n00b_cf_label_t *cf);
static n00b_cg_val_t codegen_assign(n00b_cg_session_t *s, n00b_cf_label_t *cf);
static n00b_cg_val_t codegen_varref(n00b_cg_session_t *s, n00b_cf_label_t *cf);
static n00b_cg_val_t codegen_switch(n00b_cg_session_t *s, n00b_cf_label_t *cf);
static n00b_cg_val_t codegen_unwrap_result(n00b_cg_session_t *s, n00b_cf_label_t *cf);
static n00b_cg_val_t codegen_call_cf(n00b_cg_session_t *s, n00b_cf_label_t *cf);
static n00b_parse_tree_t *codegen_find_nt_deep(n00b_parse_tree_t *node, const char *nt_name);
static bool               codegen_call_args_have_kwargs(n00b_parse_tree_t  *args_node,
                                                        n00b_parse_tree_t **kw_arg_out);
static bool               postfix_index_parts(n00b_parse_tree_t  *node,
                                              n00b_parse_tree_t **container_out,
                                              n00b_parse_tree_t **index_expr_out);
static bool          postfix_index_info(n00b_parse_tree_t *node, codegen_index_info_t *info);
static n00b_cg_val_t codegen_postfix_index(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_func_def(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_assert_stmt(n00b_cg_session_t *s, n00b_parse_tree_t *node);
static n00b_cg_val_t codegen_children_default(n00b_cg_session_t *s, n00b_parse_tree_t *node);

typedef enum {
    CODEGEN_PARAM_POSITIONAL,
    CODEGEN_PARAM_KEYWORD,
    CODEGEN_PARAM_VARGS,
} codegen_param_kind_t;

typedef struct {
    const char          *name;
    codegen_param_kind_t kind;
    n00b_cg_type_tag_t   type;
    /**
     * Registered-type-registry typehash for the parameter type, or 0
     * for primitives / unregistered shapes. Used to stamp the codegen
     * side-table so postfix-`.` extension-method dispatch can resolve
     * the receiver's registry entry. Populated in `codegen_func_meta_new`
     * by mapping the tc-type's prim name through `n00b_type_name_to_hash`.
     */
    uint64_t             type_hash;
    n00b_parse_tree_t   *default_expr;
    bool                 has_callback_sig;
    n00b_cg_type_tag_t   callback_ret_type;
    n00b_cg_type_tag_t   callback_param_types[32];
    int32_t              callback_n_params;
} codegen_param_meta_t;

typedef struct {
    const char          *name;
    n00b_cg_type_tag_t   ret_type;
    bool                 is_private;
    bool                 is_once;
    int32_t              n_params;
    int32_t              varargs_index;
    codegen_param_meta_t params[32];
} codegen_func_meta_t;

typedef struct {
    const char        *name;
    bool               is_kw;
    n00b_cg_val_t      value;
    n00b_parse_tree_t *expr;
} codegen_call_actual_t;

static char *
codegen_dup_text(const char *text, size_t len)
{
    if (!text) {
        return NULL;
    }

    char *buf = n00b_alloc_array(char, len + 1);
    memcpy(buf, text, len);
    buf[len] = '\0';
    return buf;
}

static char *
codegen_dup_token_text(n00b_parse_tree_t *tok)
{
    if (!tok) {
        return NULL;
    }

    return codegen_dup_text(n00b_pt_token_text(tok), n00b_pt_token_text_len(tok));
}

static n00b_parse_tree_t *
codegen_first_name_token(n00b_parse_tree_t *node)
{
    if (!node) {
        return NULL;
    }

    if (n00b_pt_is_token(node)) {
        const char *text = n00b_pt_token_text(node);
        size_t      len  = n00b_pt_token_text_len(node);

        if (text && len > 0 && !(len == 1 && strchr("*:=,()", text[0]))) {
            return node;
        }

        return NULL;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *found = codegen_first_name_token(n00b_pt_get_child(node, i));

        if (found) {
            return found;
        }
    }

    return NULL;
}

static bool
codegen_func_decl_has_modifier(n00b_parse_tree_t *node, const char *modifier)
{
    if (!node || !modifier) {
        return false;
    }

    n00b_parse_tree_t *mods[8];
    int                nmods = n00b_pt_collect_nt_deep(node, "func-mod", mods, 8);
    size_t             mlen  = strlen(modifier);

    for (int i = 0; i < nmods; i++) {
        n00b_parse_tree_t *tok = n00b_pt_first_token(mods[i]);

        if (!tok) {
            continue;
        }

        const char *text = n00b_pt_token_text(tok);
        size_t      len  = n00b_pt_token_text_len(tok);

        if (text && len == mlen && memcmp(text, modifier, mlen) == 0) {
            return true;
        }
    }

    return false;
}

static void
codegen_collect_param_nodes(n00b_parse_tree_t  *node,
                            n00b_parse_tree_t **out,
                            int32_t             max,
                            int32_t            *count)
{
    if (!node || !out || !count || *count >= max || n00b_pt_is_token(node)) {
        return;
    }

    if (n00b_pt_is_nt(node, "formal-param") || n00b_pt_is_nt(node, "vargs-param")) {
        out[(*count)++] = node;
        return;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc && *count < max; i++) {
        codegen_collect_param_nodes(n00b_pt_get_child(node, i), out, max, count);
    }
}

static n00b_parse_tree_t *
codegen_first_expr(n00b_parse_tree_t *node)
{
    if (!node || n00b_pt_is_token(node)) {
        return NULL;
    }

    if (n00b_pt_is_nt(node, "expression")) {
        return node;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *found = codegen_first_expr(n00b_pt_get_child(node, i));

        if (found) {
            return found;
        }
    }

    return NULL;
}

static void
codegen_fill_callback_param_signature(n00b_cg_session_t    *s,
                                      codegen_param_meta_t *param,
                                      n00b_tc_type_t       *type)
{
    if (!s || !param || !type) {
        return;
    }

    type = n00b_tc_find(type);

    if (!type || !n00b_variant_is_type(type->kind, n00b_tc_fn_t)) {
        return;
    }

    n00b_tc_fn_t fn = n00b_variant_get(type->kind, n00b_tc_fn_t);

    param->has_callback_sig = true;
    param->callback_ret_type
        = fn.return_type && s->type_map ? s->type_map(s, fn.return_type) : N00B_CG_I64;
    param->callback_n_params = 0;

    if (!fn.positional) {
        return;
    }

    size_t npos = n00b_list_len(*fn.positional);

    for (size_t i = 0; i < npos && param->callback_n_params < 32; i++) {
        n00b_tc_type_t    *arg_type = n00b_list_get(*fn.positional, i);
        n00b_cg_type_tag_t tag
            = arg_type && s->type_map ? s->type_map(s, arg_type) : N00B_CG_I64;

        param->callback_param_types[param->callback_n_params++] = tag;
    }
}

static bool
codegen_type_name_tag(const char *text, size_t len, n00b_cg_type_tag_t *tag)
{
    if (!text || !tag) {
        return false;
    }

#define CODEGEN_TYPE_NAME(lit, value)                                                          \
    if (len == sizeof(lit) - 1 && memcmp(text, lit, sizeof(lit) - 1) == 0) {                   \
        *tag = value;                                                                          \
        return true;                                                                           \
    }

    CODEGEN_TYPE_NAME("int", N00B_CG_I64)
    CODEGEN_TYPE_NAME("i64", N00B_CG_I64)
    CODEGEN_TYPE_NAME("i32", N00B_CG_I32)
    CODEGEN_TYPE_NAME("i16", N00B_CG_I16)
    CODEGEN_TYPE_NAME("i8", N00B_CG_I8)
    CODEGEN_TYPE_NAME("u64", N00B_CG_U64)
    CODEGEN_TYPE_NAME("u32", N00B_CG_U32)
    CODEGEN_TYPE_NAME("u16", N00B_CG_U16)
    CODEGEN_TYPE_NAME("u8", N00B_CG_U8)
    CODEGEN_TYPE_NAME("f64", N00B_CG_F64)
    CODEGEN_TYPE_NAME("float", N00B_CG_F64)
    CODEGEN_TYPE_NAME("f32", N00B_CG_F32)
    CODEGEN_TYPE_NAME("string", N00B_CG_STRING)
    CODEGEN_TYPE_NAME("bool", N00B_CG_BOOL)
    CODEGEN_TYPE_NAME("void", N00B_CG_VOID)

#undef CODEGEN_TYPE_NAME

    return false;
}

static void
codegen_fill_callback_param_signature_from_tokens(n00b_parse_tree_t    *param,
                                                  codegen_param_meta_t *meta)
{
    if (!param || !meta || meta->has_callback_sig) {
        return;
    }

    n00b_parse_tree_t *tokens[64];
    int32_t            ntokens = 0;
    codegen_collect_tokens_local(param, tokens, 64, &ntokens);

    int32_t open_ix  = -1;
    int32_t close_ix = -1;
    int32_t arrow_ix = -1;

    for (int32_t i = 0; i < ntokens; i++) {
        const char *text = n00b_pt_token_text(tokens[i]);
        size_t      len  = n00b_pt_token_text_len(tokens[i]);

        if (open_ix < 0 && len == 1 && text && text[0] == '(') {
            open_ix = i;
            continue;
        }

        if (open_ix >= 0 && close_ix < 0 && len == 1 && text && text[0] == ')') {
            close_ix = i;
            continue;
        }

        if (close_ix >= 0 && len == 2 && text && memcmp(text, "->", 2) == 0) {
            arrow_ix = i;
            break;
        }
    }

    if (open_ix < 0 || close_ix < 0 || arrow_ix < 0) {
        return;
    }

    meta->callback_n_params = 0;

    for (int32_t i = open_ix + 1; i < close_ix && meta->callback_n_params < 32; i++) {
        const char        *text = n00b_pt_token_text(tokens[i]);
        size_t             len  = n00b_pt_token_text_len(tokens[i]);
        n00b_cg_type_tag_t tag;

        if (codegen_type_name_tag(text, len, &tag)) {
            meta->callback_param_types[meta->callback_n_params++] = tag;
        }
    }

    for (int32_t i = arrow_ix + 1; i < ntokens; i++) {
        const char        *text = n00b_pt_token_text(tokens[i]);
        size_t             len  = n00b_pt_token_text_len(tokens[i]);
        n00b_cg_type_tag_t tag;

        if (codegen_type_name_tag(text, len, &tag)) {
            meta->callback_ret_type = tag;
            meta->has_callback_sig  = true;
            return;
        }
    }
}

static codegen_func_meta_t *
codegen_func_meta_new(n00b_cg_session_t *s,
                      const char        *func_name,
                      n00b_parse_tree_t *param_decl,
                      n00b_cg_type_tag_t ret_type,
                      bool               is_private,
                      bool               is_once)
{
    codegen_func_meta_t *meta = n00b_alloc(codegen_func_meta_t);
    meta->name                = func_name;
    meta->ret_type            = ret_type;
    meta->is_private          = is_private;
    meta->is_once             = is_once;
    meta->varargs_index       = -1;

    n00b_parse_tree_t *params[32];
    int32_t            nparams = 0;
    codegen_collect_param_nodes(param_decl, params, 32, &nparams);

    for (int32_t i = 0; i < nparams && meta->n_params < 32; i++) {
        n00b_parse_tree_t    *param = params[i];
        codegen_param_meta_t *dst   = &meta->params[meta->n_params];

        dst->has_callback_sig  = false;
        dst->callback_ret_type = N00B_CG_I64;
        dst->callback_n_params = 0;
        dst->name              = codegen_dup_token_text(codegen_first_name_token(param));

        if (!dst->name) {
            continue;
        }

        n00b_parse_tree_t *type_node = NULL;

        if (n00b_pt_is_nt(param, "vargs-param")) {
            dst->kind           = CODEGEN_PARAM_VARGS;
            dst->type           = N00B_CG_LIST;
            meta->varargs_index = meta->n_params;
        }
        else {
            n00b_parse_tree_t *kw_param = codegen_find_nt_deep(param, "k-param");

            if (kw_param) {
                dst->kind         = CODEGEN_PARAM_KEYWORD;
                dst->default_expr = codegen_first_expr(kw_param);
            }
            else {
                dst->kind = CODEGEN_PARAM_POSITIONAL;
            }

            type_node = codegen_find_nt_deep(param, "type-spec");
            if (!type_node) {
                type_node = codegen_find_nt_deep(param, "union-tspec");
            }

            dst->type = type_node ? codegen_decl_type_tag(s, type_node)
                                  : n00b_codegen_node_type(s, param);
        }

        n00b_tc_type_t *param_type = n00b_codegen_node_tc_type(s, param);

        if (param_type) {
            param_type = n00b_tc_find(param_type);
        }

        if ((!param_type || !n00b_variant_is_type(param_type->kind, n00b_tc_fn_t))
            && type_node) {
            n00b_tc_type_t *type_node_type = n00b_codegen_node_tc_type(s, type_node);

            if (type_node_type) {
                param_type = n00b_tc_find(type_node_type);
            }
        }

        codegen_fill_callback_param_signature(s, dst, param_type);
        codegen_fill_callback_param_signature_from_tokens(param, dst);

        // Resolve the parameter's runtime typehash for registry-driven
        // extension-method dispatch on the receiver. Two paths:
        //
        // (a) The tc-type path: for parameters whose annotation walk
        //     resolved their type to a prim, take the prim's name.
        // (b) The parse-tree path: when the tc-type still reads as a
        //     fresh variable (the annotation walk hasn't unified the
        //     parameter declaration with its type-spec yet), fall back
        //     to extracting the identifier text from the `type-spec`
        //     parse node. This still finds registered user-defined
        //     opaques whose name matches the BNF `<one-tspec>`
        //     identifier exactly.
        dst->type_hash = 0;
        n00b_tc_type_t *resolved_pt = param_type ? n00b_tc_find(param_type) : nullptr;

        if (resolved_pt && n00b_variant_is_type(resolved_pt->kind, n00b_tc_prim_t)) {
            n00b_tc_prim_t prim = n00b_variant_get(resolved_pt->kind, n00b_tc_prim_t);

            if (prim.name && prim.name->u8_bytes > 0 && prim.name->data) {
                char *cname = n00b_alloc_array(char, prim.name->u8_bytes + 1);
                memcpy(cname, prim.name->data, prim.name->u8_bytes);
                cname[prim.name->u8_bytes] = '\0';
                dst->type_hash             = n00b_type_name_to_hash(cname);
            }
        }

        if (!dst->type_hash && type_node) {
            // Parse-tree fallback: pull the first IDENTIFIER token
            // out of the type-spec subtree and use that as the
            // registered-type name.
            n00b_parse_tree_t *id_tok = codegen_first_name_token(type_node);

            if (id_tok) {
                char *id_text = codegen_dup_token_text(id_tok);

                if (id_text) {
                    dst->type_hash = n00b_type_name_to_hash(id_text);
                }
            }
        }

        if (dst->type == N00B_CG_PTR && dst->kind != CODEGEN_PARAM_VARGS) {
            dst->type = N00B_CG_I64;
        }

        meta->n_params++;
    }

    return meta;
}

static bool
codegen_module_has_func(n00b_cg_module_t *m, const char *name, bool include_private)
{
    if (!m || !name || !m->mir_module) {
        return false;
    }

    MIR_item_t item;
    for (item = DLIST_HEAD(MIR_item_t, m->mir_module->items); item != NULL;
         item = DLIST_NEXT(MIR_item_t, item)) {
        if (item->item_type == MIR_func_item && strcmp(item->u.func->name, name) == 0) {
            return include_private || !n00b_cg_module_func_is_private(m, name);
        }
    }

    return false;
}

static n00b_cg_module_t *
codegen_find_visible_func_module(n00b_cg_session_t *s, const char *func_name, bool *ambiguous)
{
    if (ambiguous) {
        *ambiguous = false;
    }

    if (!s || !func_name) {
        return NULL;
    }

    n00b_cg_module_t *active = s->active_module;

    if (codegen_module_has_func(active, func_name, true)) {
        return active;
    }

    n00b_cg_module_t *found = NULL;

    for (int32_t i = 0; i < s->module_count; i++) {
        n00b_cg_module_t *mod = s->modules[i];

        if (mod == active || !codegen_module_has_func(mod, func_name, false)) {
            continue;
        }

        if (found) {
            if (ambiguous) {
                *ambiguous = true;
            }

            return NULL;
        }

        found = mod;
    }

    return found;
}

static char *
codegen_func_meta_key(n00b_cg_module_t *module, const char *func_name)
{
    return codegen_module_key2(module, func_name);
}

static void
codegen_store_func_meta(n00b_cg_session_t *s, codegen_func_meta_t *meta)
{
    if (!s || !s->func_meta || !s->active_module || !meta || !meta->name) {
        return;
    }

    char *key = codegen_func_meta_key(s->active_module, meta->name);

    if (!key) {
        return;
    }

    n00b_dict_untyped_put(s->func_meta, key, meta);
}

static codegen_func_meta_t *
codegen_lookup_func_meta(n00b_cg_session_t *s, const char *func_name)
{
    if (!s || !s->func_meta || !func_name) {
        return NULL;
    }

    bool              ambiguous = false;
    n00b_cg_module_t *module    = codegen_find_visible_func_module(s, func_name, &ambiguous);

    if (!module || ambiguous) {
        return NULL;
    }

    char *key = codegen_func_meta_key(module, func_name);

    if (!key) {
        return NULL;
    }

    bool  found = false;
    void *value = n00b_dict_untyped_get(s->func_meta, key, &found);
    return found ? (codegen_func_meta_t *)value : NULL;
}

static bool
codegen_reject_ambiguous_func_call(n00b_cg_session_t *s,
                                   n00b_parse_tree_t *site,
                                   const char        *func_name)
{
    bool ambiguous = false;

    codegen_find_visible_func_module(s, func_name, &ambiguous);

    if (!ambiguous) {
        return false;
    }

    codegen_error(s, site, "CG020", "ambiguous function name imported from multiple modules");
    return true;
}

static n00b_cg_type_tag_t
codegen_lookup_func_ret_type(n00b_cg_session_t *s,
                             const char        *func_name,
                             n00b_cg_type_tag_t fallback)
{
    codegen_func_meta_t *meta = codegen_lookup_func_meta(s, func_name);

    return meta ? meta->ret_type : fallback;
}

static void
codegen_fill_callback_signature(n00b_cg_session_t  *s,
                                const char         *func_name,
                                n00b_rt_callback_t *cb)
{
    cb->ret_type      = N00B_CG_I64;
    cb->n_params      = 0;
    cb->has_signature = false;

    codegen_func_meta_t *meta = codegen_lookup_func_meta(s, func_name);

    if (!meta) {
        return;
    }

    cb->ret_type      = meta->ret_type;
    cb->has_signature = true;

    for (int32_t i = 0; i < meta->n_params && i < 32; i++) {
        cb->param_types[cb->n_params++] = meta->params[i].type;
    }
}

static n00b_class_layout_t *
codegen_receiver_class_layout(n00b_cg_session_t *s, n00b_parse_tree_t *receiver)
{
    n00b_annot_result_t *ar = current_annot(s);

    if (!ar || !ar->symtab || !receiver) {
        return NULL;
    }

    n00b_tc_type_t   *recv_type = n00b_codegen_node_tc_type(s, receiver);
    n00b_sym_entry_t *type_sym  = NULL;

    if (recv_type && n00b_variant_is_type(recv_type->kind, n00b_tc_prim_t)) {
        n00b_tc_prim_t prim = n00b_variant_get(recv_type->kind, n00b_tc_prim_t);

        if (prim.name && prim.name->u8_bytes > 0) {
            type_sym = n00b_symtab_lookup_any(ar->symtab, n00b_string_empty(), prim.name);
        }
    }

    if (!type_sym || !type_sym->exposed_scope || !type_sym->exposed_scope->scope_tag
        || type_sym->exposed_scope->scope_tag->u8_bytes != 5
        || memcmp(type_sym->exposed_scope->scope_tag->data, "class", 5) != 0) {
        return NULL;
    }

    if (!type_sym->class_layout) {
        type_sym->class_layout = compute_class_layout(s, type_sym->exposed_scope);
    }

    return type_sym->class_layout;
}

static const char *
codegen_class_method_mir_name(n00b_cg_session_t *s,
                              n00b_parse_tree_t *receiver,
                              const char        *method_name)
{
    n00b_class_layout_t *layout = codegen_receiver_class_layout(s, receiver);

    if (!layout || !method_name) {
        return NULL;
    }

    for (uint32_t mi = 0; mi < layout->n_methods; mi++) {
        if (strcmp(layout->method_names[mi], method_name) == 0) {
            return layout->method_mir_names[mi];
        }
    }

    return NULL;
}

static bool
codegen_reject_private_cross_module_call(n00b_cg_session_t *s,
                                         n00b_parse_tree_t *site,
                                         const char        *func_name)
{
    bool ambiguous = false;

    if (codegen_find_visible_func_module(s, func_name, &ambiguous) || ambiguous) {
        return false;
    }

    if (!n00b_cg_func_is_private_in_other_module(s, func_name)) {
        return false;
    }

    codegen_error(s, site, "CG021", "private function is not visible outside its module");
    return true;
}

static codegen_func_meta_t *
codegen_current_func_meta(n00b_cg_session_t *s)
{
    n00b_cg_module_t *m = s ? s->active_module : NULL;

    if (!m || !m->cur_func) {
        return NULL;
    }

    return codegen_lookup_func_meta(s, m->cur_func->u.func->name);
}

static codegen_param_meta_t *
codegen_meta_param_named(codegen_func_meta_t *meta, const char *name)
{
    if (!meta || !name) {
        return NULL;
    }

    for (int32_t i = 0; i < meta->n_params; i++) {
        if (meta->params[i].name && strcmp(meta->params[i].name, name) == 0) {
            return &meta->params[i];
        }
    }

    return NULL;
}

static codegen_param_meta_t *
codegen_callback_param_meta_for_actual(n00b_cg_session_t *s, codegen_call_actual_t *actual)
{
    if (!actual || actual->is_kw || actual->value.kind == N00B_CG_VAL_IMM) {
        return NULL;
    }

    n00b_parse_tree_t *name_tok = codegen_first_name_token(actual->expr);

    if (!name_tok) {
        return NULL;
    }

    char *name = codegen_dup_token_text(name_tok);

    if (!name) {
        return NULL;
    }

    codegen_param_meta_t *param = codegen_meta_param_named(codegen_current_func_meta(s), name);

    if (!param || !param->has_callback_sig) {
        return NULL;
    }

    return param;
}

static n00b_rt_callback_t *
codegen_local_callback_for_actual(n00b_cg_session_t *s, codegen_call_actual_t *actual)
{
    if (!actual || actual->is_kw || actual->value.kind == N00B_CG_VAL_IMM) {
        return NULL;
    }

    n00b_parse_tree_t *name_tok = codegen_first_name_token(actual->expr);

    if (!name_tok) {
        return NULL;
    }

    char *name = codegen_dup_token_text(name_tok);

    return name ? codegen_lookup_local_callback(s, name) : NULL;
}

static int32_t
codegen_meta_param_index(codegen_func_meta_t *meta, const char *name)
{
    if (!meta || !name) {
        return -1;
    }

    for (int32_t i = 0; i < meta->n_params; i++) {
        if (meta->params[i].name && strcmp(meta->params[i].name, name) == 0) {
            return i;
        }
    }

    return -1;
}

static n00b_cg_val_t
codegen_list_from_values(n00b_cg_session_t *s, n00b_cg_val_t *values, int32_t n_values)
{
    n00b_cg_import_func(s,
                        "n00b_builtin_list_new",
                        (void *)n00b_builtin_list_new,
                        .ret = N00B_CG_I64);

    n00b_cg_val_t list
        = n00b_cg_emit_call(s, "n00b_builtin_list_new", NULL, 0, .ret = N00B_CG_I64);
    list.type_tag = N00B_CG_LIST;

    if (n_values <= 0) {
        return list;
    }

    n00b_cg_type_tag_t push_pt[] = {N00B_CG_I64, N00B_CG_I64, N00B_CG_I64};
    n00b_cg_import_func(s,
                        "n00b_builtin_list_push_value",
                        (void *)n00b_builtin_list_push_value,
                        .ret         = N00B_CG_VOID,
                        .param_types = push_pt,
                        .n_params    = 3);

    for (int32_t i = 0; i < n_values; i++) {
        n00b_cg_val_t value_tag = _n00b_cg_const_i64(s, (int64_t)values[i].type_tag);
        n00b_cg_val_t args[]    = {list, values[i], value_tag};
        n00b_cg_emit_call(s, "n00b_builtin_list_push_value", args, 3, .ret = N00B_CG_VOID);
    }

    return list;
}

static bool
codegen_type_hint_can_refine(n00b_cg_type_tag_t current, n00b_cg_type_tag_t hint)
{
    if (hint == N00B_CG_PTR || hint == N00B_CG_VOID || current == hint) {
        return false;
    }

    return current == N00B_CG_I64 || current == N00B_CG_PTR;
}

static void
codegen_collect_call_actuals(n00b_cg_session_t     *s,
                             n00b_parse_tree_t     *node,
                             codegen_call_actual_t *out,
                             int32_t                max,
                             int32_t               *count)
{
    if (!node || !out || !count || *count >= max || n00b_pt_is_token(node)) {
        return;
    }

    if (n00b_pt_is_nt(node, "call-kw-arg")) {
        n00b_parse_tree_t *name_tok = n00b_pt_first_token(node);
        n00b_parse_tree_t *expr     = codegen_first_expr(node);

        if (name_tok && expr) {
            n00b_cg_val_t value = codegen_walk(s, expr);

            if (s->has_codegen_errors || value.kind == N00B_CG_VAL_VOID) {
                return;
            }

            n00b_cg_type_tag_t expr_tag = n00b_codegen_node_type(s, expr);

            if (codegen_type_hint_can_refine(value.type_tag, expr_tag)) {
                value.type_tag = expr_tag;
            }

            out[*count] = (codegen_call_actual_t){
                .name  = codegen_dup_token_text(name_tok),
                .is_kw = true,
                .value = value,
                .expr  = expr,
            };
            (*count)++;
        }

        return;
    }

    if (n00b_pt_is_nt(node, "expression")) {
        n00b_cg_val_t value = codegen_walk(s, node);

        if (s->has_codegen_errors || value.kind == N00B_CG_VAL_VOID) {
            return;
        }

        n00b_cg_type_tag_t expr_tag = n00b_codegen_node_type(s, node);

        if (codegen_type_hint_can_refine(value.type_tag, expr_tag)) {
            value.type_tag = expr_tag;
        }

        out[*count] = (codegen_call_actual_t){
            .name  = NULL,
            .is_kw = false,
            .value = value,
            .expr  = node,
        };
        (*count)++;
        return;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc && *count < max; i++) {
        codegen_collect_call_actuals(s, n00b_pt_get_child(node, i), out, max, count);

        if (s->has_codegen_errors) {
            return;
        }
    }
}

static bool
codegen_bind_call_actuals(n00b_cg_session_t     *s,
                          n00b_parse_tree_t     *site,
                          const char            *func_name,
                          codegen_call_actual_t *actuals,
                          int32_t                n_actuals,
                          n00b_cg_val_t         *bound,
                          int32_t               *n_bound)
{
    if (codegen_reject_ambiguous_func_call(s, site, func_name)) {
        return false;
    }

    codegen_func_meta_t *meta = codegen_lookup_func_meta(s, func_name);

    if (!meta) {
        for (int32_t i = 0; i < n_actuals && *n_bound < 32; i++) {
            bound[(*n_bound)++] = actuals[i].value;
        }

        return true;
    }

    n00b_cg_val_t filled[32];
    bool          has_value[32] = {0};
    n00b_cg_val_t vararg_values[32];
    int32_t       n_varargs       = 0;
    int32_t       next_positional = 0;

    for (int32_t i = 0; i < n_actuals; i++) {
        if (actuals[i].is_kw) {
            int32_t param_ix = codegen_meta_param_index(meta, actuals[i].name);

            if (param_ix < 0 || meta->params[param_ix].kind == CODEGEN_PARAM_VARGS) {
                codegen_error(s, site, "CG020", "unknown keyword argument");
                return false;
            }

            if (has_value[param_ix]) {
                codegen_error(s, site, "CG020", "keyword argument was provided more than once");
                return false;
            }

            filled[param_ix]    = actuals[i].value;
            has_value[param_ix] = true;
            continue;
        }

        if (meta->varargs_index >= 0 && next_positional >= meta->varargs_index) {
            if (n_varargs < 32) {
                vararg_values[n_varargs++] = actuals[i].value;
            }
            continue;
        }

        while (next_positional < meta->n_params
               && meta->params[next_positional].kind == CODEGEN_PARAM_VARGS) {
            next_positional++;
        }

        if (next_positional < meta->n_params) {
            filled[next_positional]    = actuals[i].value;
            has_value[next_positional] = true;
            next_positional++;
            continue;
        }

        codegen_error(s, site, "CG020", "too many positional arguments");
        return false;
    }

    for (int32_t i = 0; i < meta->n_params && *n_bound < 32; i++) {
        codegen_param_meta_t *param = &meta->params[i];

        if (param->kind == CODEGEN_PARAM_VARGS) {
            bound[(*n_bound)++] = codegen_list_from_values(s, vararg_values, n_varargs);
            continue;
        }

        if (has_value[i]) {
            bound[(*n_bound)++] = filled[i];
            continue;
        }

        if (param->default_expr) {
            n00b_cg_val_t value = codegen_walk(s, param->default_expr);

            if (s->has_codegen_errors || value.kind == N00B_CG_VAL_VOID) {
                return false;
            }

            bound[(*n_bound)++] = value;
            continue;
        }

        codegen_error(s, site, "CG020", "missing required function argument");
        return false;
    }

    if (meta->varargs_index >= meta->n_params && *n_bound < 32) {
        bound[(*n_bound)++] = codegen_list_from_values(s, vararg_values, n_varargs);
    }

    return true;
}

static void
codegen_import_once_helpers(n00b_cg_session_t *s)
{
    n00b_cg_type_tag_t one_pt[] = {N00B_CG_I64};
    n00b_cg_import_func(s,
                        "n00b_builtin_once_is_done",
                        (void *)n00b_builtin_once_is_done,
                        .ret         = N00B_CG_I64,
                        .param_types = one_pt,
                        .n_params    = 1);
    n00b_cg_import_func(s,
                        "n00b_builtin_once_get_i64",
                        (void *)n00b_builtin_once_get_i64,
                        .ret         = N00B_CG_I64,
                        .param_types = one_pt,
                        .n_params    = 1);
    n00b_cg_import_func(s,
                        "n00b_builtin_once_get_f32",
                        (void *)n00b_builtin_once_get_f32,
                        .ret         = N00B_CG_F32,
                        .param_types = one_pt,
                        .n_params    = 1);
    n00b_cg_import_func(s,
                        "n00b_builtin_once_get_f64",
                        (void *)n00b_builtin_once_get_f64,
                        .ret         = N00B_CG_F64,
                        .param_types = one_pt,
                        .n_params    = 1);

    n00b_cg_type_tag_t store_pt[] = {N00B_CG_I64, N00B_CG_I64};
    n00b_cg_import_func(s,
                        "n00b_builtin_once_store_i64",
                        (void *)n00b_builtin_once_store_i64,
                        .ret         = N00B_CG_VOID,
                        .param_types = store_pt,
                        .n_params    = 2);

    n00b_cg_type_tag_t store_f32_pt[] = {N00B_CG_I64, N00B_CG_F32};
    n00b_cg_import_func(s,
                        "n00b_builtin_once_store_f32",
                        (void *)n00b_builtin_once_store_f32,
                        .ret         = N00B_CG_VOID,
                        .param_types = store_f32_pt,
                        .n_params    = 2);

    n00b_cg_type_tag_t store_f64_pt[] = {N00B_CG_I64, N00B_CG_F64};
    n00b_cg_import_func(s,
                        "n00b_builtin_once_store_f64",
                        (void *)n00b_builtin_once_store_f64,
                        .ret         = N00B_CG_VOID,
                        .param_types = store_f64_pt,
                        .n_params    = 2);
}

static n00b_cg_val_t
codegen_once_key(n00b_cg_session_t *s)
{
    return _n00b_cg_const_i64(s, (int64_t)s->current_once_key);
}

static const char *
codegen_once_get_helper(n00b_cg_type_tag_t type)
{
    if (type == N00B_CG_F32) {
        return "n00b_builtin_once_get_f32";
    }

    if (type == N00B_CG_F64) {
        return "n00b_builtin_once_get_f64";
    }

    return "n00b_builtin_once_get_i64";
}

static const char *
codegen_once_store_helper(n00b_cg_type_tag_t type)
{
    if (type == N00B_CG_F32) {
        return "n00b_builtin_once_store_f32";
    }

    if (type == N00B_CG_F64) {
        return "n00b_builtin_once_store_f64";
    }

    return "n00b_builtin_once_store_i64";
}

static n00b_cg_val_t
codegen_zero_for_type(n00b_cg_session_t *s, n00b_cg_type_tag_t type)
{
    if (type == N00B_CG_F32) {
        return _n00b_cg_const_f32(s, 0.0f);
    }

    if (type == N00B_CG_F64) {
        return _n00b_cg_const_f64(s, 0.0);
    }

    return _n00b_cg_const_i64(s, 0);
}

static void
codegen_once_store_return(n00b_cg_session_t *s, n00b_cg_val_t value)
{
    if (!s || s->current_once_key == 0) {
        return;
    }

    codegen_import_once_helpers(s);
    n00b_cg_val_t key = codegen_once_key(s);

    if (value.kind == N00B_CG_VAL_VOID) {
        value = _n00b_cg_const_i64(s, 0);
    }

    const char   *helper = codegen_once_store_helper(value.type_tag);
    n00b_cg_val_t args[] = {key, value};
    n00b_cg_emit_call(s, helper, args, 2, .ret = N00B_CG_VOID);
}

// ============================================================================
// Short-circuit logical operators
// ============================================================================

static n00b_cg_val_t
codegen_short_circuit(n00b_cg_session_t    *s,
                      n00b_cg_semantic_op_t op,
                      n00b_parse_tree_t    *left,
                      n00b_parse_tree_t    *right)
{
    n00b_cg_val_t result      = n00b_cg_temp(s, N00B_CG_I64);
    n00b_cg_val_t short_label = n00b_cg_label_new(s);
    n00b_cg_val_t end_label   = n00b_cg_label_new(s);

    n00b_cg_val_t left_val = codegen_walk(s, left);

    if (op == N00B_CG_OP_LOGICAL_AND) {
        n00b_cg_emit_bf(s, left_val, short_label);
    }
    else {
        n00b_cg_emit_bt(s, left_val, short_label);
    }

    n00b_cg_val_t right_val = codegen_walk(s, right);
    n00b_cg_store(s, result, right_val);
    n00b_cg_emit_jmp(s, end_label);

    n00b_cg_label_here(s, short_label);

    if (op == N00B_CG_OP_LOGICAL_AND) {
        n00b_cg_store(s, result, _n00b_cg_const_i64(s, 0));
    }
    else {
        n00b_cg_store(s, result, _n00b_cg_const_i64(s, 1));
    }

    n00b_cg_label_here(s, end_label);

    return result;
}

// ============================================================================
// Operator codegen
// ============================================================================

static n00b_cg_val_t
codegen_operator(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    size_t n_children = n00b_pt_num_children(node);

    const char *op_text = NULL;

    for (size_t i = 0; i < n_children; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (n00b_pt_is_token(child)) {
            op_text = n00b_pt_token_text(child);
            break;
        }
    }

    if (!op_text) {
        return codegen_children_default(s, node);
    }

    size_t op_len = strlen(op_text);
    char   op_buf[32];

    if (op_len >= sizeof(op_buf)) {
        op_len = sizeof(op_buf) - 1;
    }

    memcpy(op_buf, op_text, op_len);
    op_buf[op_len] = '\0';

    int32_t sem_op = n00b_cg_lookup_op(s, op_buf);

    if (sem_op < 0) {
        return codegen_children_default(s, node);
    }

    n00b_parse_tree_t *operands[8];
    int                n_operands = 0;

    for (size_t i = 0; i < n_children && n_operands < 8; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (!n00b_pt_is_token(child)) {
            operands[n_operands++] = child;
        }
    }

    if (n_operands == 2) {
        if (sem_op == N00B_CG_OP_LOGICAL_AND || sem_op == N00B_CG_OP_LOGICAL_OR) {
            return codegen_short_circuit(s,
                                         (n00b_cg_semantic_op_t)sem_op,
                                         operands[0],
                                         operands[1]);
        }

        n00b_cg_val_t a = codegen_walk(s, operands[0]);
        n00b_cg_val_t b = codegen_walk(s, operands[1]);

        return n00b_cg_emit_binop(s, (n00b_cg_semantic_op_t)sem_op, a, b);
    }

    if (n_operands == 1) {
        // Unary '-' is negation, not subtraction.
        if (sem_op == N00B_CG_OP_SUB) {
            sem_op = N00B_CG_OP_NEG;
        }

        n00b_cg_val_t a = codegen_walk(s, operands[0]);
        return n00b_cg_emit_unop(s, (n00b_cg_semantic_op_t)sem_op, a);
    }

    return codegen_children_default(s, node);
}

// ============================================================================
// Literal codegen
// ============================================================================

static n00b_cg_val_t
codegen_literal(n00b_cg_session_t *s, n00b_parse_tree_t *node, n00b_annotation_t *annot)
{
    n00b_cg_type_tag_t type = n00b_codegen_node_type(s, node);

    n00b_parse_tree_t *tok_node = n00b_pt_first_token(node);

    if (!tok_node) {
        return _n00b_cg_const_i64(s, 0);
    }

    n00b_string_t *lit_kind = annot->op_kind;

    if (s->literal_parser) {
        return s->literal_parser(s, tok_node, lit_kind, type);
    }

    return default_literal_parser(s, tok_node, lit_kind, type);
}

// ============================================================================
// Embed literal codegen
// ============================================================================

static n00b_cg_val_t
codegen_embed(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    // Find the EMBED token (first token child).
    n00b_parse_tree_t *tok_node = n00b_pt_first_token(node);
    n00b_token_info_t *tok      = tok_node ? n00b_parse_node_token(tok_node) : nullptr;

    if (!tok || !n00b_option_is_set(tok->value)) {
        return N00B_CG_VOID_VAL;
    }

    n00b_string_t *content = n00b_option_get(tok->value);

    // Extract modifier.  The tokenizer stores the 'ffi suffix in
    // tok->modifier.  Fall back to a <type-spec> grammar child if the
    // tokenizer didn't capture it (shouldn't happen in practice).
    n00b_string_t *modifier = nullptr;

    if (n00b_option_is_set(tok->modifier)) {
        modifier = n00b_option_get(tok->modifier);
    }
    else {
        n00b_parse_tree_t *ts_nodes[1] = {NULL};

        if (n00b_pt_collect_nt_deep(node, "type-spec", ts_nodes, 1) > 0) {
            n00b_parse_tree_t *id_tok = n00b_pt_first_token(ts_nodes[0]);

            if (id_tok) {
                const char *text = n00b_pt_token_text(id_tok);
                size_t      tlen = n00b_pt_token_text_len(id_tok);

                if (text && tlen > 0) {
                    modifier = n00b_string_from_raw(text, (int64_t)tlen);
                }
            }
        }
    }

    if (!modifier) {
        bool looks_like_ffi = false;

        if (content && content->data) {
            bool saw_arrow = false;
            bool saw_eq    = false;

            for (size_t i = 0; i < content->u8_bytes; i++) {
                if (content->data[i] == '=') {
                    saw_eq = true;
                }
                else if (content->data[i] == '-' && i + 1 < content->u8_bytes
                         && content->data[i + 1] == '>') {
                    saw_arrow = true;
                }
            }

            looks_like_ffi = saw_arrow && saw_eq;
        }

        if (looks_like_ffi) {
            modifier = n00b_string_from_cstr("ffi");
        }
        else {
            codegen_error(s, node, "CG001", "embed literal: no type modifier specified");
            return N00B_CG_VOID_VAL;
        }
    }

    if (!s->embed_registry) {
        codegen_error(s, node, "CG002", "embed literal: no embed registry configured");
        return N00B_CG_VOID_VAL;
    }

    n00b_embed_result_t r = n00b_embed_dispatch(s->embed_registry, s, content, modifier);

    // Cast the opaque 16-byte result back to n00b_cg_val_t.
    n00b_cg_val_t val;
    _Static_assert(sizeof(val) == sizeof(r),
                   "n00b_cg_val_t and n00b_embed_result_t must be same size");
    memcpy(&val, &r, sizeof(val));
    return val;
}

// ============================================================================
// Auto-inferred call codegen
// ============================================================================

static n00b_cg_val_t
codegen_call_auto(n00b_cg_session_t *s, n00b_parse_tree_t *node, n00b_annotation_t *annot)
{
    n00b_parse_tree_t *func_node = NULL;
    n00b_parse_tree_t *args_node = NULL;

    if (annot->name_ref.kind == N00B_ROLE_BY_INDEX) {
        int32_t idx = annot->name_ref.index;

        if (idx >= 0) {
            func_node = n00b_pt_get_child(node, (size_t)idx);
        }
    }

    if (annot->value_ref.kind == N00B_ROLE_BY_INDEX && annot->value_ref.index >= 0) {
        args_node = n00b_pt_get_child(node, (size_t)annot->value_ref.index);
    }
    else if (annot->type_ref.kind == N00B_ROLE_BY_INDEX && annot->type_ref.index >= 0) {
        args_node = n00b_pt_get_child(node, (size_t)annot->type_ref.index);
    }

    const char *func_name = NULL;

    if (func_node) {
        n00b_parse_tree_t *name_tok = n00b_pt_first_token(func_node);

        if (name_tok) {
            func_name = n00b_pt_token_text(name_tok);
        }
    }

    if (!func_name) {
        return codegen_children_default(s, node);
    }

    codegen_call_actual_t actuals[32];
    int32_t               n_actuals = 0;

    codegen_collect_call_actuals(s, args_node, actuals, 32, &n_actuals);

    if (s->has_codegen_errors) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_val_t args[32];
    int32_t       n_args = 0;

    if (!codegen_bind_call_actuals(s,
                                   args_node ? args_node : node,
                                   func_name,
                                   actuals,
                                   n_actuals,
                                   args,
                                   &n_args)) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_type_tag_t   ret_type = n00b_codegen_node_type(s, node);
    codegen_func_meta_t *meta     = codegen_lookup_func_meta(s, func_name);

    if (meta) {
        ret_type = meta->ret_type;
    }

    if (codegen_reject_private_cross_module_call(s, node, func_name)) {
        return N00B_CG_VOID_VAL;
    }

    return n00b_cg_emit_call(s, func_name, args, n_args, .ret = ret_type);
}

// ============================================================================
// Control flow codegen
// ============================================================================

static n00b_parse_tree_t *
codegen_first_direct_nt_child(n00b_parse_tree_t *node, const char *nt_name)
{
    if (!node || !nt_name || n00b_pt_is_token(node)) {
        return NULL;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (!child || n00b_pt_is_token(child)) {
            continue;
        }

        if (n00b_pt_is_group(child)) {
            n00b_parse_tree_t *found = codegen_first_direct_nt_child(child, nt_name);

            if (found) {
                return found;
            }

            continue;
        }

        if (n00b_pt_is_nt(child, nt_name)) {
            return child;
        }
    }

    return NULL;
}

static n00b_parse_tree_t *
codegen_first_direct_nt_child_any(n00b_parse_tree_t *node, const char **nt_names, int n_names)
{
    if (!node || !nt_names || n_names <= 0 || n00b_pt_is_token(node)) {
        return NULL;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (!child || n00b_pt_is_token(child)) {
            continue;
        }

        if (n00b_pt_is_group(child)) {
            n00b_parse_tree_t *found
                = codegen_first_direct_nt_child_any(child, nt_names, n_names);

            if (found) {
                return found;
            }

            continue;
        }

        for (int i_name = 0; i_name < n_names; i_name++) {
            if (n00b_pt_is_nt(child, nt_names[i_name])) {
                return child;
            }
        }
    }

    return NULL;
}

static bool
codegen_is_nt_any(n00b_parse_tree_t *node, const char **nt_names, int n_names)
{
    if (!node || !nt_names || n_names <= 0 || n00b_pt_is_token(node)) {
        return false;
    }

    for (int i = 0; i < n_names; i++) {
        if (n00b_pt_is_nt(node, nt_names[i])) {
            return true;
        }
    }

    return false;
}

static bool
codegen_is_block_structure(n00b_parse_tree_t *node)
{
    if (!node || n00b_pt_is_token(node)) {
        return false;
    }

    if (n00b_pt_is_group(node)) {
        return true;
    }

    const char *names[] = {
        "body",
        "case-body",
        "yielding-body",
        "yielding-case-body",
        "body-stmts",
        "body-stmt-list",
        "yielding-body-stmts",
        "block-value-expr",
    };

    return codegen_is_nt_any(node, names, (int)(sizeof(names) / sizeof(names[0])));
}

static bool
codegen_is_ignorable_block_child(n00b_parse_tree_t *node)
{
    if (!node || n00b_pt_is_token(node)) {
        return true;
    }

    const char *names[] = {
        "eos",
        "block-start",
        "block-end",
    };

    return codegen_is_nt_any(node, names, (int)(sizeof(names) / sizeof(names[0])));
}

static bool
codegen_block_child_has_statement(n00b_parse_tree_t *node)
{
    if (!node || n00b_pt_is_token(node) || codegen_is_ignorable_block_child(node)) {
        return false;
    }

    if (!codegen_is_block_structure(node)) {
        return true;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        if (codegen_block_child_has_statement(n00b_pt_get_child(node, i))) {
            return true;
        }
    }

    return false;
}

static bool
codegen_single_non_token_child(n00b_parse_tree_t *node,
                               n00b_parse_tree_t **child_out,
                               bool               *saw_token)
{
    if (child_out) {
        *child_out = NULL;
    }

    if (saw_token) {
        *saw_token = false;
    }

    if (!node || n00b_pt_is_token(node)) {
        return false;
    }

    n00b_parse_tree_t *only = NULL;
    size_t             nc   = n00b_pt_num_children(node);
    int                seen = 0;

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (!child) {
            continue;
        }

        if (n00b_pt_is_token(child)) {
            if (saw_token) {
                *saw_token = true;
            }

            continue;
        }

        only = child;
        seen++;
    }

    if (seen != 1) {
        return false;
    }

    if (child_out) {
        *child_out = only;
    }

    return true;
}

static bool
codegen_is_value_yield_expr(n00b_parse_tree_t *node)
{
    return n00b_pt_is_nt(node, "block-value-expr") || n00b_pt_is_nt(node, "if-value-expr")
        || n00b_pt_is_nt(node, "switch-value-expr");
}

static bool
codegen_tuple_or_paren_is_grouping(n00b_parse_tree_t *node, n00b_parse_tree_t **expr_out)
{
    if (expr_out) {
        *expr_out = NULL;
    }

    if (!node || !n00b_pt_is_nt(node, "tuple-or-paren")) {
        return false;
    }

    n00b_parse_tree_t *expr = NULL;
    size_t             nc   = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (!child || n00b_pt_is_token(child)) {
            continue;
        }

        if (n00b_pt_is_nt(child, "expr-comma-list") || n00b_pt_is_nt(child, "named-field-list")
            || n00b_pt_is_nt(child, "type-spec")) {
            return false;
        }

        if (n00b_pt_is_nt(child, "expression")) {
            if (expr) {
                return false;
            }

            expr = child;
        }
        else {
            return false;
        }
    }

    if (!expr) {
        return false;
    }

    if (expr_out) {
        *expr_out = expr;
    }

    return true;
}

static bool
codegen_expression_stmt_has_direct_yield_value(n00b_parse_tree_t *node)
{
    n00b_parse_tree_t *cur = node;

    while (cur && !n00b_pt_is_token(cur)) {
        if (codegen_is_value_yield_expr(cur)) {
            return true;
        }

        n00b_parse_tree_t *next = NULL;

        if (codegen_tuple_or_paren_is_grouping(cur, &next)) {
            cur = next;
            continue;
        }

        bool saw_token = false;

        if (!codegen_single_non_token_child(cur, &next, &saw_token) || saw_token) {
            return false;
        }

        cur = next;
    }

    return false;
}

static bool
codegen_tree_contains_statement_yield(n00b_parse_tree_t *node)
{
    if (!node || n00b_pt_is_token(node)) {
        return false;
    }

    if (n00b_pt_is_nt(node, "yield-stmt")) {
        return true;
    }

    if (n00b_pt_is_nt(node, "expression-stmt")) {
        return codegen_expression_stmt_has_direct_yield_value(node);
    }

    if (codegen_is_value_yield_expr(node) || n00b_pt_is_nt(node, "return-stmt")
        || n00b_pt_is_nt(node, "variable-decl") || n00b_pt_is_nt(node, "assign-stmt")
        || n00b_pt_is_nt(node, "binop-assign-stmt") || n00b_pt_is_nt(node, "assert-stmt")) {
        return false;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        if (codegen_tree_contains_statement_yield(n00b_pt_get_child(node, i))) {
            return true;
        }
    }

    return false;
}

static bool
codegen_store_yield_value(n00b_cg_session_t  *s,
                          n00b_parse_tree_t  *site,
                          n00b_cg_val_t       value,
                          n00b_cg_val_t      *result,
                          n00b_cg_type_tag_t *result_type,
                          bool               *have_result)
{
    if (value.kind == N00B_CG_VAL_VOID) {
        return false;
    }

    if (!*have_result) {
        *result      = n00b_cg_temp(s, value.type_tag);
        *result_type = value.type_tag;
        *have_result = true;
    }
    else if (value.type_tag != *result_type) {
        codegen_error(s,
                      site,
                      "CG022",
                      "yield arms in this block produce incompatible value types");
        return false;
    }

    n00b_cg_store(s, *result, value);
    return true;
}

static n00b_cg_val_t
codegen_block_value(n00b_cg_session_t *s, n00b_parse_tree_t *block, bool *yielded);

static n00b_cg_val_t
codegen_statement_value(n00b_cg_session_t *s, n00b_parse_tree_t *node, bool *yielded)
{
    *yielded = false;

    if (!node || n00b_pt_is_token(node)) {
        return N00B_CG_VOID_VAL;
    }

    if (n00b_pt_is_group(node)) {
        bool          saw_stmt     = false;
        bool          last_yielded = false;
        n00b_cg_val_t result       = N00B_CG_VOID_VAL;
        size_t        nc           = n00b_pt_num_children(node);

        for (size_t i = 0; i < nc; i++) {
            bool          child_yielded = false;
            n00b_cg_val_t child_val
                = codegen_statement_value(s, n00b_pt_get_child(node, i), &child_yielded);

            if (s->has_codegen_errors) {
                break;
            }

            if (child_val.kind != N00B_CG_VAL_VOID) {
                result = child_val;
            }

            if (child_yielded || child_val.kind != N00B_CG_VAL_VOID) {
                saw_stmt     = true;
                last_yielded = child_yielded;
            }
        }

        *yielded = saw_stmt && last_yielded;
        return *yielded ? result : N00B_CG_VOID_VAL;
    }

    if (n00b_pt_is_nt(node, "body-stmt")) {
        size_t nc = n00b_pt_num_children(node);

        for (size_t i = 0; i < nc; i++) {
            n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

            if (!child || n00b_pt_is_token(child) || codegen_is_ignorable_block_child(child)) {
                continue;
            }

            return codegen_statement_value(s, child, yielded);
        }

        return N00B_CG_VOID_VAL;
    }

    if (n00b_pt_is_nt(node, "yield-stmt")) {
        n00b_cg_val_t result = codegen_walk(s, node);
        *yielded             = result.kind != N00B_CG_VAL_VOID;
        return result;
    }

    if (n00b_pt_is_nt(node, "expression-stmt")
        && codegen_expression_stmt_has_direct_yield_value(node)) {
        n00b_cg_val_t result = codegen_walk(s, node);
        *yielded             = result.kind != N00B_CG_VAL_VOID;
        return result;
    }

    const char *value_cf_names[] = {
        "if-stmt",
        "if-value-expr",
        "switch-stmt",
        "switch-value-expr",
    };

    if (codegen_is_nt_any(node,
                          value_cf_names,
                          (int)(sizeof(value_cf_names) / sizeof(value_cf_names[0])))) {
        n00b_cg_val_t result = codegen_walk(s, node);
        *yielded             = result.kind != N00B_CG_VAL_VOID;
        return result;
    }

    n00b_cg_val_t result = codegen_walk(s, node);
    *yielded             = false;
    return result;
}

static n00b_cg_val_t
codegen_block_sequence(n00b_cg_session_t *s,
                       n00b_parse_tree_t *node,
                       bool              *yielded,
                       bool              *saw_stmt)
{
    *yielded  = false;
    *saw_stmt = false;

    if (!node || n00b_pt_is_token(node)) {
        return N00B_CG_VOID_VAL;
    }

    if (!codegen_is_block_structure(node)) {
        *saw_stmt = true;
        return codegen_statement_value(s, node, yielded);
    }

    n00b_cg_val_t result = N00B_CG_VOID_VAL;
    size_t        nc     = n00b_pt_num_children(node);
    size_t        last_statement_child = SIZE_MAX;

    for (size_t i = 0; i < nc; i++) {
        if (codegen_block_child_has_statement(n00b_pt_get_child(node, i))) {
            last_statement_child = i;
        }
    }

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (!child || n00b_pt_is_token(child) || codegen_is_ignorable_block_child(child)) {
            continue;
        }

        bool          child_yielded  = false;
        bool          child_saw_stmt = false;
        n00b_cg_val_t child_val      = N00B_CG_VOID_VAL;
        bool          saved_reject   = s->reject_unconsumed_yield;

        if (i != last_statement_child) {
            s->reject_unconsumed_yield = true;
        }

        if (codegen_is_block_structure(child)) {
            child_val = codegen_block_sequence(s, child, &child_yielded, &child_saw_stmt);
        }
        else {
            child_saw_stmt = true;
            child_val      = codegen_statement_value(s, child, &child_yielded);
        }

        s->reject_unconsumed_yield = saved_reject;

        if (s->has_codegen_errors) {
            break;
        }

        if (!child_saw_stmt) {
            continue;
        }

        *saw_stmt = true;
        *yielded  = child_yielded;

        if (child_val.kind != N00B_CG_VAL_VOID) {
            result = child_val;
        }
    }

    return *yielded ? result : N00B_CG_VOID_VAL;
}

static n00b_cg_val_t
codegen_block_value(n00b_cg_session_t *s, n00b_parse_tree_t *block, bool *yielded)
{
    bool          saw_stmt = false;
    n00b_cg_val_t result   = codegen_block_sequence(s, block, yielded, &saw_stmt);

    if (!saw_stmt || !*yielded) {
        *yielded = false;
        return N00B_CG_VOID_VAL;
    }

    return result;
}

typedef struct {
    n00b_parse_tree_t **elifs;
    int                 n_elifs;
    int                 elif_cap;
    n00b_parse_tree_t *else_body;
} codegen_elif_parts_t;

static void
codegen_elif_parts_push(codegen_elif_parts_t *parts, n00b_parse_tree_t *elif_node)
{
    if (parts->n_elifs >= parts->elif_cap) {
        int new_cap = parts->elif_cap ? parts->elif_cap * 2 : 8;
        n00b_parse_tree_t **new_elifs
            = n00b_alloc_array(n00b_parse_tree_t *, (size_t)new_cap);

        if (parts->elifs) {
            memcpy(new_elifs, parts->elifs, sizeof(n00b_parse_tree_t *) * parts->n_elifs);
        }

        parts->elifs    = new_elifs;
        parts->elif_cap = new_cap;
    }

    parts->elifs[parts->n_elifs++] = elif_node;
}

static n00b_parse_tree_t *
codegen_else_clause_body(n00b_parse_tree_t *node)
{
    const char *body_names[] = {"body", "yielding-body"};

    return codegen_first_direct_nt_child_any(node,
                                             body_names,
                                             (int)(sizeof(body_names) / sizeof(body_names[0])));
}

static void
codegen_collect_elif_parts(n00b_parse_tree_t *node, codegen_elif_parts_t *parts)
{
    if (!node || !parts || n00b_pt_is_token(node)) {
        return;
    }

    if (n00b_pt_is_nt(node, "elif-clause") || n00b_pt_is_nt(node, "yielding-elif-clause")) {
        codegen_elif_parts_push(parts, node);
        return;
    }

    if (n00b_pt_is_nt(node, "else-clause") || n00b_pt_is_nt(node, "yielding-else-clause")) {
        parts->else_body = codegen_else_clause_body(node);
        return;
    }

    if (!n00b_pt_is_group(node) && !n00b_pt_is_nt(node, "elif-chain")
        && !n00b_pt_is_nt(node, "yielding-elif-chain")) {
        return;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        codegen_collect_elif_parts(n00b_pt_get_child(node, i), parts);
    }
}

static n00b_cg_val_t
codegen_elif_chain(n00b_cg_session_t *s,
                   n00b_parse_tree_t *chain,
                   bool              *yielded,
                   bool               require_value)
{
    *yielded = false;

    codegen_elif_parts_t parts = {0};
    codegen_collect_elif_parts(chain, &parts);

    if (parts.n_elifs == 0) {
        if (parts.else_body) {
            return codegen_block_value(s, parts.else_body, yielded);
        }

        return N00B_CG_VOID_VAL;
    }

    n00b_cg_val_t      result      = N00B_CG_VOID_VAL;
    n00b_cg_type_tag_t result_type = N00B_CG_VOID;
    bool               have_result = false;
    bool               all_yield   = true;
    n00b_cg_val_t      chain_end   = n00b_cg_label_new(s);

    for (int i = 0; i < parts.n_elifs; i++) {
        n00b_cf_label_t *cf         = n00b_codegen_cf_label(s, parts.elifs[i]);
        n00b_cg_val_t    next_label = n00b_cg_label_new(s);

        if (!cf || !cf->cond || !cf->then_body) {
            all_yield = false;
            continue;
        }

        n00b_cg_val_t cond = codegen_walk(s, cf->cond);

        if (s->has_codegen_errors || cond.kind == N00B_CG_VAL_VOID) {
            all_yield = false;
            break;
        }

        n00b_cg_emit_bf(s, cond, next_label);

        bool          arm_yielded = false;
        n00b_cg_val_t arm_value   = codegen_block_value(s, cf->then_body, &arm_yielded);

        if (arm_yielded) {
            codegen_store_yield_value(s,
                                      parts.elifs[i],
                                      arm_value,
                                      &result,
                                      &result_type,
                                      &have_result);
        }
        else {
            all_yield = false;
        }

        n00b_cg_emit_jmp(s, chain_end);
        n00b_cg_label_here(s, next_label);
    }

    if (parts.else_body) {
        bool          else_yielded = false;
        n00b_cg_val_t else_value   = codegen_block_value(s, parts.else_body, &else_yielded);

        if (else_yielded) {
            codegen_store_yield_value(s,
                                      parts.else_body,
                                      else_value,
                                      &result,
                                      &result_type,
                                      &have_result);
        }
        else {
            all_yield = false;
        }
    }
    else {
        all_yield = false;
    }

    n00b_cg_label_here(s, chain_end);

    if (all_yield && have_result && !s->has_codegen_errors) {
        *yielded = true;
        return result;
    }

    if (require_value && !s->has_codegen_errors) {
        codegen_error(s, chain, "CG022", "value-producing if does not yield on every path");
    }

    return N00B_CG_VOID_VAL;
}

static n00b_cg_val_t
codegen_else_branch_value(n00b_cg_session_t *s,
                          n00b_parse_tree_t *else_node,
                          bool              *yielded,
                          bool               require_value)
{
    *yielded = false;

    if (!else_node) {
        return N00B_CG_VOID_VAL;
    }

    if (n00b_pt_is_nt(else_node, "elif-chain")
        || n00b_pt_is_nt(else_node, "yielding-elif-chain")) {
        return codegen_elif_chain(s, else_node, yielded, require_value);
    }

    if (n00b_pt_is_nt(else_node, "else-clause")
        || n00b_pt_is_nt(else_node, "yielding-else-clause")) {
        n00b_parse_tree_t *body = codegen_else_clause_body(else_node);
        return codegen_block_value(s, body, yielded);
    }

    return codegen_block_value(s, else_node, yielded);
}

static n00b_cg_val_t
codegen_branch_common(n00b_cg_session_t *s, n00b_cf_label_t *cf, bool require_value)
{
    n00b_cg_val_t      else_label  = n00b_cg_label_new(s);
    n00b_cg_val_t      end_label   = n00b_cg_label_new(s);
    n00b_cg_val_t      result      = N00B_CG_VOID_VAL;
    n00b_cg_type_tag_t result_type = N00B_CG_VOID;
    bool               have_result = false;

    n00b_cg_val_t cond = codegen_walk(s, cf->cond);

    if (s->has_codegen_errors || cond.kind == N00B_CG_VAL_VOID) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_emit_bf(s, cond, else_label);

    bool          then_yielded = false;
    n00b_cg_val_t then_value   = N00B_CG_VOID_VAL;

    if (cf->then_body) {
        then_value = codegen_block_value(s, cf->then_body, &then_yielded);
    }

    if (then_yielded) {
        codegen_store_yield_value(s,
                                  cf->then_body,
                                  then_value,
                                  &result,
                                  &result_type,
                                  &have_result);
    }

    n00b_cg_emit_jmp(s, end_label);

    n00b_cg_label_here(s, else_label);

    bool          else_yielded = false;
    n00b_cg_val_t else_value
        = codegen_else_branch_value(s, cf->else_body, &else_yielded, require_value);

    if (else_yielded) {
        codegen_store_yield_value(s,
                                  cf->else_body,
                                  else_value,
                                  &result,
                                  &result_type,
                                  &have_result);
    }

    n00b_cg_label_here(s, end_label);

    if (then_yielded && else_yielded && have_result && !s->has_codegen_errors) {
        return result;
    }

    if (require_value && !s->has_codegen_errors) {
        codegen_error(s, cf->self, "CG022", "value-producing if does not yield on every path");
    }

    return N00B_CG_VOID_VAL;
}

static n00b_cg_val_t
codegen_branch(n00b_cg_session_t *s, n00b_cf_label_t *cf)
{
    return codegen_branch_common(s, cf, false);
}

static n00b_cg_val_t
codegen_block_value_expr(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    bool          yielded = false;
    bool          saved_reject = s->reject_unconsumed_yield;
    s->reject_unconsumed_yield = false;
    n00b_cg_val_t result       = codegen_block_value(s, node, &yielded);
    s->reject_unconsumed_yield = saved_reject;

    if (!yielded && !s->has_codegen_errors) {
        codegen_error(s, node, "CG022", "block expression does not end with yield");
    }

    return result;
}

static n00b_cg_val_t
codegen_if_value_expr(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    n00b_cf_label_t *cf = n00b_codegen_cf_label(s, node);

    if (!cf) {
        return codegen_children_default(s, node);
    }

    bool          saved_reject = s->reject_unconsumed_yield;
    s->reject_unconsumed_yield = false;
    n00b_cg_val_t result       = codegen_branch_common(s, cf, true);
    s->reject_unconsumed_yield = saved_reject;
    return result;
}

// Check if a for-loop's condition is a range node (for x in start to end).
static bool
is_range_loop(n00b_cf_label_t *cf)
{
    if (!cf->cond) {
        return false;
    }

    return n00b_pt_is_nt(cf->cond, "range");
}

// Extract the loop variable name from a for-stmt node.
// for-stmt children: 'for', for-var-list, 'in'/'from', range/target, body
static const char *
extract_loop_var_name(n00b_cg_session_t *s, n00b_cf_label_t *cf)
{
    n00b_parse_tree_t *self = cf->self;
    size_t             nc   = n00b_pt_num_children(self);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(self, i);

        if (child && n00b_pt_is_nt(child, "for-var-list")) {
            n00b_parse_tree_t *tok = n00b_pt_first_token(child);

            if (tok) {
                const char *text = n00b_pt_token_text(tok);
                size_t      len  = n00b_pt_token_text_len(tok);

                if (text && len > 0) {
                    char *buf = n00b_alloc_array(char, len + 1);
                    memcpy(buf, text, len);
                    buf[len] = '\0';
                    return buf;
                }
            }
        }
    }

    return NULL;
}

// Extract start and end expressions from a range node.
// range -> range-parts -> expression, range-sep, expression
static bool
extract_range_bounds(n00b_cg_session_t  *s,
                     n00b_parse_tree_t  *range_node,
                     n00b_parse_tree_t **start_out,
                     n00b_parse_tree_t **end_out)
{
    // range -> range-parts (single child or direct)
    n00b_parse_tree_t *parts = range_node;

    // Descend through range to range-parts if needed.
    size_t nc = n00b_pt_num_children(parts);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(parts, i);

        if (child && n00b_pt_is_nt(child, "range-parts")) {
            parts = child;
            break;
        }
    }

    // range-parts has children: expression, range-sep, expression
    // Find the first two non-token, non-group NTs that are expressions.
    n00b_parse_tree_t *exprs[2] = {NULL, NULL};
    int                n_exprs  = 0;

    nc = n00b_pt_num_children(parts);

    for (size_t i = 0; i < nc && n_exprs < 2; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(parts, i);

        if (!child || n00b_pt_is_token(child)) {
            continue;
        }

        if (n00b_pt_is_group(child)) {
            continue;
        }

        // Skip range-sep nodes.
        if (n00b_pt_is_nt(child, "range-sep")) {
            continue;
        }

        exprs[n_exprs++] = child;
    }

    if (n_exprs < 2) {
        return false;
    }

    *start_out = exprs[0];
    *end_out   = exprs[1];
    return true;
}

// Push a loop entry onto the loop stack.
static void
push_loop(n00b_cg_session_t *s, n00b_cg_val_t break_label, n00b_cg_val_t continue_label)
{
    n00b_cg_module_t *m = s->active_module;

    if (m->loop_depth >= m->loop_cap) {
        int32_t               new_cap = m->loop_cap ? m->loop_cap * 2 : 8;
        n00b_cg_loop_entry_t *new_stack
            = n00b_alloc_array(n00b_cg_loop_entry_t, (size_t)new_cap);
        if (m->loop_stack) {
            memcpy(new_stack,
                   m->loop_stack,
                   sizeof(n00b_cg_loop_entry_t) * (size_t)m->loop_depth);
        }

        m->loop_stack = new_stack;
        m->loop_cap   = new_cap;
    }

    m->loop_stack[m->loop_depth++] = (n00b_cg_loop_entry_t){
        .break_label    = break_label,
        .continue_label = continue_label,
    };
}

static void
codegen_loop_body(n00b_cg_session_t *s, n00b_parse_tree_t *body)
{
    if (!body) {
        return;
    }

    bool yielded = false;
    (void)codegen_block_value(s, body, &yielded);

    if (yielded && !s->has_codegen_errors) {
        codegen_error(s, body, "CG022", "loop body cannot yield a value");
    }
}

static n00b_cg_val_t
codegen_loop(n00b_cg_session_t *s, n00b_cf_label_t *cf)
{
    n00b_cg_module_t *m = s->active_module;

    // Check if this is a for-in-range loop.
    if (is_range_loop(cf)) {
        const char *var_name = extract_loop_var_name(s, cf);

        n00b_parse_tree_t *start_node = NULL;
        n00b_parse_tree_t *end_node   = NULL;

        if (!var_name || !extract_range_bounds(s, cf->cond, &start_node, &end_node)) {
            return N00B_CG_VOID_VAL;
        }

        // Evaluate start and end bounds.
        n00b_cg_val_t start_val = codegen_walk(s, start_node);
        n00b_cg_val_t end_val   = codegen_walk(s, end_node);

        // Create the loop variable, initialize to start.
        n00b_cg_val_t loop_var = n00b_cg_local(s, var_name, .type = N00B_CG_I64);
        n00b_cg_store(s, loop_var, start_val);

        // Store end in a temp so it's not re-evaluated each iteration.
        n00b_cg_val_t end_tmp = n00b_cg_temp(s, N00B_CG_I64);
        n00b_cg_store(s, end_tmp, end_val);

        n00b_cg_val_t test_label     = n00b_cg_label_new(s);
        n00b_cg_val_t break_label    = n00b_cg_label_new(s);
        n00b_cg_val_t continue_label = n00b_cg_label_new(s);

        push_loop(s, break_label, continue_label);

        // Test: loop_var < end
        n00b_cg_label_here(s, test_label);
        n00b_cg_val_t cond = n00b_cg_emit_binop(s, N00B_CG_OP_LT, loop_var, end_tmp);
        n00b_cg_emit_bf(s, cond, break_label);

        codegen_loop_body(s, cf->then_body);

        // Continue: increment and jump to test.
        n00b_cg_label_here(s, continue_label);
        n00b_cg_val_t one = _n00b_cg_const_i64(s, 1);
        n00b_cg_val_t inc = n00b_cg_emit_binop(s, N00B_CG_OP_ADD, loop_var, one);
        n00b_cg_store(s, loop_var, inc);
        n00b_cg_emit_jmp(s, test_label);

        n00b_cg_label_here(s, break_label);

        m->loop_depth--;
        return N00B_CG_VOID_VAL;
    }

    // While-style loop: condition + body.
    n00b_cg_val_t continue_label = n00b_cg_label_new(s);
    n00b_cg_val_t break_label    = n00b_cg_label_new(s);

    push_loop(s, break_label, continue_label);

    n00b_cg_label_here(s, continue_label);

    if (cf->cond) {
        n00b_cg_val_t cond = codegen_walk(s, cf->cond);
        n00b_cg_emit_bf(s, cond, break_label);
    }

    codegen_loop_body(s, cf->then_body);

    n00b_cg_emit_jmp(s, continue_label);

    n00b_cg_label_here(s, break_label);

    m->loop_depth--;

    return N00B_CG_VOID_VAL;
}

static n00b_cg_val_t
codegen_jump(n00b_cg_session_t *s, n00b_cf_label_t *cf)
{
    n00b_cg_module_t *m  = s->active_module;
    const char       *jk = cf->jump_kind ? cf->jump_kind->data : NULL;

    if (!jk) {
        return N00B_CG_VOID_VAL;
    }

    if (strncmp(jk, "return", 6) == 0) {
        size_t nc = n00b_pt_num_children(cf->self);

        for (size_t i = 0; i < nc; i++) {
            n00b_parse_tree_t *child = n00b_pt_get_child(cf->self, i);

            if (!n00b_pt_is_token(child)) {
                n00b_cg_val_t val = codegen_walk(s, child);
                codegen_once_store_return(s, val);
                n00b_cg_emit_ret(s, val);
                return N00B_CG_VOID_VAL;
            }
        }

        codegen_once_store_return(s, N00B_CG_VOID_VAL);
        n00b_cg_emit_ret_void(s);
        return N00B_CG_VOID_VAL;
    }

    if (strncmp(jk, "break", 5) == 0) {
        if (m->loop_depth > 0) {
            n00b_cg_emit_jmp(s, m->loop_stack[m->loop_depth - 1].break_label);
        }
        return N00B_CG_VOID_VAL;
    }

    if (strncmp(jk, "continue", 8) == 0) {
        if (m->loop_depth > 0) {
            n00b_cg_emit_jmp(s, m->loop_stack[m->loop_depth - 1].continue_label);
        }
        return N00B_CG_VOID_VAL;
    }

    return N00B_CG_VOID_VAL;
}

// Compound assignment operator table: token text -> base operator text.
static const struct {
    const char *compound;
    const char *base;
} compound_assign_ops[] = {
    {"+=", "+"},
    {"-=", "-"},
    {"*=", "*"},
    {"/=", "/"},
    {"%=", "%"},
    {"&=", "&"},
    {"|=", "|"},
    {"^=", "^"},
    {"<<=", "<<"},
    {">>=", ">>"},
};

#define NUM_COMPOUND_OPS (sizeof(compound_assign_ops) / sizeof(compound_assign_ops[0]))

// Find compound assignment operator token in cf->self children.
// Returns the base operator string (e.g. "+" for "+="), or NULL for simple "=".
static const char *
find_compound_op(n00b_parse_tree_t *self_node)
{
    size_t nc = n00b_pt_num_children(self_node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(self_node, i);

        // The operator is in child $1 (<binop-assign-op>), which may
        // be a non-terminal containing a single token, or the token
        // itself might be directly found via first_token.
        n00b_parse_tree_t *tok = n00b_pt_first_token(child);

        if (!tok) {
            continue;
        }

        const char *text = n00b_pt_token_text(tok);
        size_t      tlen = n00b_pt_token_text_len(tok);

        if (!text || tlen == 0) {
            continue;
        }

        for (size_t j = 0; j < NUM_COMPOUND_OPS; j++) {
            size_t clen = strlen(compound_assign_ops[j].compound);

            if (tlen == clen && memcmp(text, compound_assign_ops[j].compound, clen) == 0) {
                return compound_assign_ops[j].base;
            }
        }
    }

    return NULL;
}

static n00b_parse_tree_t *
find_postfix_index_node(n00b_parse_tree_t *node)
{
    if (!node || n00b_pt_is_token(node)) {
        return NULL;
    }

    codegen_index_info_t info = {0};

    if (postfix_index_info(node, &info)) {
        return node;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *found = find_postfix_index_node(n00b_pt_get_child(node, i));

        if (found) {
            return found;
        }
    }

    return NULL;
}

static n00b_cg_val_t
codegen_index_bound_or_default(n00b_cg_session_t *s,
                               n00b_parse_tree_t *expr,
                               int64_t            default_value)
{
    if (!expr) {
        return _n00b_cg_const_i64(s, default_value);
    }

    return codegen_walk(s, expr);
}

// Track semantic type tags for local variables.
static n00b_cg_val_t
codegen_assign(n00b_cg_session_t *s, n00b_cf_label_t *cf)
{
    n00b_cg_val_t value = N00B_CG_VOID_VAL;

    if (cf->then_body) {
        value = codegen_walk(s, cf->then_body);
    }

    if (s->has_codegen_errors) {
        return N00B_CG_VOID_VAL;
    }

    // Indexed assignment: list[index] = value.
    if (cf->cond && value.kind != N00B_CG_VAL_VOID && !find_compound_op(cf->self)) {
        n00b_parse_tree_t   *index_lhs = find_postfix_index_node(cf->cond);
        codegen_index_info_t info      = {0};

        if (index_lhs && postfix_index_info(index_lhs, &info)) {
            n00b_cg_val_t container = codegen_walk(s, info.container);

            if (container.kind != N00B_CG_VAL_VOID) {
                n00b_cg_type_tag_t container_type = container.type_tag;

                if (container_type != N00B_CG_LIST && container_type != N00B_CG_DICT
                    && container_type != N00B_CG_STRING && container_type != N00B_CG_SET) {
                    n00b_cg_type_tag_t inferred = n00b_codegen_node_type(s, info.container);

                    if (inferred == N00B_CG_LIST || inferred == N00B_CG_DICT
                        || inferred == N00B_CG_STRING || inferred == N00B_CG_SET) {
                        container.type_tag = inferred;
                        container_type     = inferred;
                    }
                }

                if (container_type == N00B_CG_LIST) {
                    if (info.is_slice) {
                        if (value.type_tag != N00B_CG_LIST) {
                            codegen_error(s,
                                          index_lhs,
                                          "CG010",
                                          "list slice assignment requires a list value");
                            return N00B_CG_VOID_VAL;
                        }

                        n00b_cg_val_t start = codegen_index_bound_or_default(s, info.start, 0);
                        n00b_cg_val_t end   = codegen_index_bound_or_default(s, info.end, 0);

                        if (start.kind == N00B_CG_VAL_VOID || end.kind == N00B_CG_VAL_VOID) {
                            return N00B_CG_VOID_VAL;
                        }

                        n00b_cg_type_tag_t slice_pt[] = {N00B_CG_LIST,
                                                         N00B_CG_I64,
                                                         N00B_CG_I64,
                                                         N00B_CG_I64,
                                                         N00B_CG_I64,
                                                         N00B_CG_LIST};

                        n00b_cg_import_func(s,
                                            "n00b_builtin_list_slice_assign",
                                            (void *)n00b_builtin_list_slice_assign,
                                            .ret         = N00B_CG_VOID,
                                            .param_types = slice_pt,
                                            .n_params    = 6);

                        n00b_cg_val_t has_start = _n00b_cg_const_i64(s, info.has_start ? 1 : 0);
                        n00b_cg_val_t has_end   = _n00b_cg_const_i64(s, info.has_end ? 1 : 0);
                        n00b_cg_val_t args[]
                            = {container, start, has_start, end, has_end, value};
                        n00b_cg_emit_call(s,
                                          "n00b_builtin_list_slice_assign",
                                          args,
                                          6,
                                          .ret = N00B_CG_VOID);
                        return value;
                    }

                    n00b_cg_val_t index = codegen_walk(s, info.start);

                    if (index.kind != N00B_CG_VAL_VOID) {
                        n00b_cg_type_tag_t set_pt[]
                            = {N00B_CG_LIST, N00B_CG_I64, N00B_CG_I64, N00B_CG_I64};

                        n00b_cg_import_func(s,
                                            "n00b_builtin_list_set_value",
                                            (void *)n00b_builtin_list_set_value,
                                            .ret         = N00B_CG_VOID,
                                            .param_types = set_pt,
                                            .n_params    = 4);

                        n00b_cg_val_t value_tag
                            = _n00b_cg_const_i64(s, (int64_t)value.type_tag);
                        n00b_cg_val_t args[] = {container, index, value, value_tag};
                        n00b_cg_emit_call(s,
                                          "n00b_builtin_list_set_value",
                                          args,
                                          4,
                                          .ret = N00B_CG_VOID);
                        return value;
                    }
                }
                else if (container_type == N00B_CG_DICT) {
                    if (info.is_slice) {
                        codegen_error(s,
                                      index_lhs,
                                      "CG010",
                                      "dictionary slices are not supported; use a single key");
                        return N00B_CG_VOID_VAL;
                    }

                    n00b_cg_val_t key = codegen_walk(s, info.start);

                    if (key.kind != N00B_CG_VAL_VOID) {
                        n00b_cg_type_tag_t put_pt[] = {N00B_CG_DICT,
                                                       N00B_CG_I64,
                                                       N00B_CG_I64,
                                                       N00B_CG_I64,
                                                       N00B_CG_I64};

                        n00b_cg_import_func(s,
                                            "n00b_builtin_dict_put_value",
                                            (void *)n00b_builtin_dict_put_value,
                                            .ret         = N00B_CG_VOID,
                                            .param_types = put_pt,
                                            .n_params    = 5);

                        n00b_cg_val_t key_tag = _n00b_cg_const_i64(s, (int64_t)key.type_tag);
                        n00b_cg_val_t value_tag
                            = _n00b_cg_const_i64(s, (int64_t)value.type_tag);
                        n00b_cg_val_t args[] = {container, key, key_tag, value, value_tag};
                        n00b_cg_emit_call(s,
                                          "n00b_builtin_dict_put_value",
                                          args,
                                          5,
                                          .ret = N00B_CG_VOID);
                        return value;
                    }
                }
                else if (container_type == N00B_CG_STRING) {
                    codegen_error(s,
                                  index_lhs,
                                  "CG010",
                                  "string index and slice assignment is not supported");
                    return N00B_CG_VOID_VAL;
                }
                else if (container_type == N00B_CG_SET) {
                    codegen_error(s, index_lhs, "CG010", "set values are not indexable");
                    return N00B_CG_VOID_VAL;
                }
            }

            codegen_error(s,
                          index_lhs,
                          "CG010",
                          "this indexed assignment is not supported by the MIR JIT");
            return N00B_CG_VOID_VAL;
        }
    }

    // Check for field assignment: self.x = val or obj.field = val.
    // The cf->cond is the <expression> wrapping the LHS. We need to
    // find the innermost postfix-expr that has a '.' token.
    if (cf->cond) {
        // Walk down expression wrappers to find the postfix-expr with a dot.
        n00b_parse_tree_t *dot_node = NULL;
        {
            n00b_parse_tree_t *walk_stack[64];
            int                walk_sp = 0;
            walk_stack[walk_sp++]      = cf->cond;

            while (walk_sp > 0 && !dot_node) {
                n00b_parse_tree_t *cur = walk_stack[--walk_sp];

                if (!cur || n00b_pt_is_token(cur)) {
                    continue;
                }

                // Check if this node has a '.' token child.
                size_t cnc = n00b_pt_num_children(cur);

                for (size_t ci = 0; ci < cnc; ci++) {
                    n00b_parse_tree_t *cc = n00b_pt_get_child(cur, ci);

                    if (n00b_pt_is_token(cc)) {
                        const char *ct  = n00b_pt_token_text(cc);
                        size_t      ctl = n00b_pt_token_text_len(cc);

                        if (ctl == 1 && ct[0] == '.') {
                            dot_node = cur;
                            break;
                        }
                    }
                }

                if (!dot_node) {
                    // Push children for deeper search.
                    for (size_t ci = 0; ci < cnc && walk_sp < 63; ci++) {
                        n00b_parse_tree_t *cc = n00b_pt_get_child(cur, ci);

                        if (cc && !n00b_pt_is_token(cc)) {
                            walk_stack[walk_sp++] = cc;
                        }
                    }
                }
            }
        }

        bool               has_dot      = false;
        n00b_parse_tree_t *fa_lhs       = NULL;
        const char        *fa_field     = NULL;
        size_t             fa_field_len = 0;

        if (dot_node) {
            size_t anc = n00b_pt_num_children(dot_node);

            for (size_t i = 0; i < anc; i++) {
                n00b_parse_tree_t *child = n00b_pt_get_child(dot_node, i);

                if (n00b_pt_is_token(child)) {
                    const char *t  = n00b_pt_token_text(child);
                    size_t      tl = n00b_pt_token_text_len(child);

                    if (tl == 1 && t[0] == '.') {
                        has_dot = true;
                    }
                    else if (has_dot && tl > 0) {
                        fa_field     = t;
                        fa_field_len = tl;
                    }
                }
                else if (!has_dot) {
                    fa_lhs = child;
                }
            }
        }

        if (has_dot && fa_lhs && fa_field && fa_field_len > 0) {
            // Field assignment: evaluate receiver, find layout, emit field_set.
            n00b_cg_val_t obj = codegen_walk(s, fa_lhs);

            if (obj.kind != N00B_CG_VAL_VOID) {
                n00b_annot_result_t *ar       = current_annot(s);
                n00b_sym_entry_t    *type_sym = NULL;

                if (ar && ar->symtab) {
                    // Try type-based lookup.
                    n00b_tc_type_t *lhs_type = n00b_codegen_node_tc_type(s, fa_lhs);

                    if (lhs_type && n00b_variant_is_type(lhs_type->kind, n00b_tc_prim_t)) {
                        n00b_tc_prim_t prim = n00b_variant_get(lhs_type->kind, n00b_tc_prim_t);

                        if (prim.name && prim.name->u8_bytes > 0) {
                            type_sym = n00b_symtab_lookup_any(ar->symtab,
                                                              n00b_string_empty(),
                                                              prim.name);
                        }
                    }

                    // Fallback for self inside method.
                    if (!type_sym) {
                        n00b_parse_tree_t *vt = n00b_pt_first_token(fa_lhs);

                        if (vt) {
                            const char *vn = n00b_pt_token_text(vt);
                            size_t      vl = n00b_pt_token_text_len(vt);

                            if (vn && vl == 4 && memcmp(vn, "self", 4) == 0) {
                                n00b_cg_module_t *m = s->active_module;

                                if (m && m->cur_func) {
                                    const char *fname  = m->cur_func->u.func->name;
                                    const char *dollar = strchr(fname, '$');

                                    if (dollar) {
                                        size_t         clen = (size_t)(dollar - fname);
                                        n00b_string_t *cname
                                            = n00b_string_from_raw(fname, (int64_t)clen);
                                        type_sym = n00b_symtab_lookup_any(ar->symtab,
                                                                          n00b_string_empty(),
                                                                          cname);
                                    }
                                }
                            }
                        }
                    }
                }

                if (type_sym && type_sym->exposed_scope) {
                    if (!type_sym->class_layout) {
                        type_sym->class_layout
                            = compute_class_layout(s, type_sym->exposed_scope);
                    }

                    n00b_class_layout_t *layout = type_sym->class_layout;

                    if (layout) {
                        int32_t fidx = layout_field_index(layout, fa_field, fa_field_len);

                        if (fidx >= 0) {
                            n00b_cg_type_tag_t set_pt[]
                                = {N00B_CG_I64, N00B_CG_I64, N00B_CG_I64};
                            const char *set_name = s->current_attr_lock_on_write
                                                     ? "n00b_builtin_field_set_and_lock"
                                                     : "n00b_builtin_field_set";
                            void       *set_addr = s->current_attr_lock_on_write
                                                     ? (void *)n00b_builtin_field_set_and_lock
                                                     : (void *)n00b_builtin_field_set;
                            n00b_cg_import_func(s,
                                                set_name,
                                                set_addr,
                                                .ret         = N00B_CG_VOID,
                                                .param_types = set_pt,
                                                .n_params    = 3);
                            n00b_cg_val_t offset_arg
                                = _n00b_cg_const_i64(s, (int64_t)layout->field_offsets[fidx]);
                            n00b_cg_val_t set_args[] = {obj, offset_arg, value};
                            n00b_cg_emit_call(s, set_name, set_args, 3, .ret = N00B_CG_VOID);
                            return value;
                        }
                    }
                }
            }
        }
    }

    if (s->current_attr_lock_on_write) {
        codegen_error(s,
                      cf->cond ? cf->cond : cf->self,
                      "CG019",
                      "attribute lock syntax requires a field assignment");
        return N00B_CG_VOID_VAL;
    }

    if (cf->cond) {
        n00b_parse_tree_t *name_tok = n00b_pt_first_token(cf->cond);

        if (name_tok) {
            const char *var_name = n00b_pt_token_text(name_tok);

            if (var_name) {
                // Check for compound assignment (+=, -=, etc.).
                const char *base_op = find_compound_op(cf->self);

                if (base_op) {
                    // Compound: load current value, apply binop, store back.
                    n00b_cg_module_t *m    = s->active_module;
                    MIR_func_t        func = m->cur_func->u.func;
                    size_t            nlen = n00b_pt_token_text_len(name_tok);
                    char              nbuf[128];

                    if (nlen >= sizeof(nbuf)) {
                        nlen = sizeof(nbuf) - 1;
                    }

                    memcpy(nbuf, var_name, nlen);
                    nbuf[nlen] = '\0';

                    MIR_reg_t     reg = MIR_reg(s->mir_ctx, nbuf, func);
                    n00b_cg_val_t lhs = (n00b_cg_val_t){
                        .id       = (uint32_t)reg,
                        .kind     = N00B_CG_VAL_REG,
                        .type_tag = value.type_tag,
                    };

                    int32_t sem_op = n00b_cg_lookup_op(s, base_op);

                    if (sem_op >= 0) {
                        n00b_cg_val_t result
                            = n00b_cg_emit_binop(s, (n00b_cg_semantic_op_t)sem_op, lhs, value);
                        n00b_cg_store(s, lhs, result);
                        codegen_store_local_type(s, nbuf, result.type_tag);
                        return lhs;
                    }
                }

                // Simple assignment: try to look up existing register first,
                // only create a new local if it doesn't exist yet.
                n00b_cg_module_t *m2    = s->active_module;
                MIR_func_t        fn2   = m2->cur_func->u.func;
                size_t            nlen2 = n00b_pt_token_text_len(name_tok);
                char              nbuf2[128];

                if (nlen2 >= sizeof(nbuf2)) {
                    nlen2 = sizeof(nbuf2) - 1;
                }

                memcpy(nbuf2, var_name, nlen2);
                nbuf2[nlen2] = '\0';

                n00b_cg_val_t dst;
                MIR_reg_t     existing  = 0;
                bool          found_reg = false;

                // Check if register already exists (re-assignment).
                for (uint32_t ri = 0; ri < VARR_LENGTH(MIR_var_t, fn2->vars); ri++) {
                    MIR_var_t v = VARR_GET(MIR_var_t, fn2->vars, ri);

                    if (v.name && strcmp(v.name, nbuf2) == 0) {
                        existing  = MIR_reg(s->mir_ctx, nbuf2, fn2);
                        found_reg = true;
                        break;
                    }
                }

                if (found_reg) {
                    dst = (n00b_cg_val_t){
                        .id       = (uint32_t)existing,
                        .kind     = N00B_CG_VAL_REG,
                        .type_tag = value.type_tag,
                    };
                }
                else {
                    dst = n00b_cg_local(s, nbuf2, .type = value.type_tag);
                }

                n00b_cg_store(s, dst, value);
                codegen_store_local_type(s, nbuf2, value.type_tag);
                if (value.type_tag == N00B_CG_FUNC && value.kind == N00B_CG_VAL_IMM
                    && value.aux) {
                    codegen_store_local_callback(s,
                                                 nbuf2,
                                                 (n00b_rt_callback_t *)(uintptr_t)value.aux);
                }
                if (value.type_tag == N00B_CG_PTR && value.aux) {
                    codegen_store_local_layout(s,
                                               nbuf2,
                                               (n00b_class_layout_t *)(uintptr_t)value.aux);
                }
                return dst;
            }
        }
    }

    return value;
}

static n00b_cg_val_t
codegen_lock_attr_stmt(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    n00b_cf_label_t *cf = n00b_codegen_cf_label(s, node);

    if (!cf || cf->kind != N00B_CF_ASSIGNS) {
        codegen_error(s, node, "CG019", "attribute lock syntax requires assignment");
        return N00B_CG_VOID_VAL;
    }

    bool saved                    = s->current_attr_lock_on_write;
    s->current_attr_lock_on_write = true;

    n00b_cg_val_t result = codegen_assign(s, cf);

    s->current_attr_lock_on_write = saved;
    return result;
}

static n00b_cg_val_t
codegen_varref(n00b_cg_session_t *s, n00b_cf_label_t *cf)
{
    n00b_cg_module_t *m = s->active_module;

    if (cf->cond) {
        n00b_parse_tree_t *name_tok = n00b_pt_first_token(cf->cond);

        if (name_tok) {
            const char *var_name = n00b_pt_token_text(name_tok);

            if (var_name && m->cur_func) {
                MIR_func_t func = m->cur_func->u.func;
                size_t     len  = n00b_pt_token_text_len(name_tok);
                char       buf[128];

                if (len >= sizeof(buf)) {
                    len = sizeof(buf) - 1;
                }

                memcpy(buf, var_name, len);
                buf[len] = '\0';

                MIR_reg_t reg = MIR_reg(s->mir_ctx, buf, func);

                // Try node_types first (has the properly unified type
                // from the annotation walk). If not found, look up
                // the sym entry and try to resolve through the type
                // system. The symtab entry's type_var may not be
                // unified for variables declared without explicit types.
                n00b_cg_type_tag_t    tag = n00b_codegen_node_type(s, cf->self);
                codegen_param_meta_t *param
                    = codegen_meta_param_named(codegen_current_func_meta(s), buf);

                if (param) {
                    tag = param->type;
                }

                n00b_cg_type_tag_t local_tag;

                if (codegen_lookup_local_type(s, buf, &local_tag)) {
                    tag = local_tag;
                }

                n00b_cg_type_tag_t mir_param_tag;

                if (codegen_lookup_param_mir_type(func, buf, &mir_param_tag)
                    && (mir_param_tag == N00B_CG_F32 || mir_param_tag == N00B_CG_F64
                        || tag == N00B_CG_I64)) {
                    tag = mir_param_tag;
                }

                return (n00b_cg_val_t){
                    .id       = (uint32_t)reg,
                    .kind     = N00B_CG_VAL_REG,
                    .type_tag = tag,
                };
            }
        }
    }

    return N00B_CG_VOID_VAL;
}

// ============================================================================
// Unwrap result (postfix !)
// ============================================================================

static n00b_cg_val_t
codegen_unwrap_result(n00b_cg_session_t *s, n00b_cf_label_t *cf)
{
    if (!cf || !cf->self) {
        return N00B_CG_VOID_VAL;
    }

    n00b_parse_tree_t *operand_node = NULL;
    size_t             nc           = n00b_pt_num_children(cf->self);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(cf->self, i);

        if (child && !n00b_pt_is_token(child)) {
            operand_node = child;
            break;
        }
    }

    if (!operand_node) {
        codegen_error(s, cf->self, "CG018", "postfix ! is missing an operand");
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_val_t operand = codegen_walk(s, operand_node);

    if (s->has_codegen_errors || operand.kind == N00B_CG_VAL_VOID) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_type_tag_t operand_node_type = n00b_codegen_node_type(s, operand_node);

    if ((operand.type_tag != N00B_CG_OPTION && operand.type_tag != N00B_CG_RESULT)
        && (operand_node_type == N00B_CG_OPTION || operand_node_type == N00B_CG_RESULT)) {
        operand.type_tag = operand_node_type;
    }

    bool is_option = operand.type_tag == N00B_CG_OPTION;
    bool is_result = operand.type_tag == N00B_CG_RESULT;

    if (!is_option && !is_result) {
        codegen_error(s, cf->self, "CG018", "postfix ! requires an option or result value");
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_type_tag_t enclosing_ret = s->current_func_ret_type;
    n00b_cg_type_tag_t needed_ret    = is_option ? N00B_CG_OPTION : N00B_CG_RESULT;

    if (enclosing_ret != needed_ret) {
        codegen_error(s,
                      cf->self,
                      "CG018",
                      "postfix ! can only propagate from a function returning the same option "
                      "or result kind");
        return N00B_CG_VOID_VAL;
    }

    const char *check_name
        = is_option ? "n00b_builtin_option_is_set" : "n00b_builtin_result_is_ok";
    void *check_addr
        = is_option ? (void *)n00b_builtin_option_is_set : (void *)n00b_builtin_result_is_ok;

    n00b_cg_type_tag_t check_pt[] = {N00B_CG_I64};
    n00b_cg_import_func(s,
                        check_name,
                        check_addr,
                        .ret         = N00B_CG_I64,
                        .param_types = check_pt,
                        .n_params    = 1);

    n00b_cg_val_t cond     = n00b_cg_emit_call(s, check_name, &operand, 1, .ret = N00B_CG_I64);
    n00b_cg_val_t ok_label = n00b_cg_label_new(s);

    n00b_cg_emit_bt(s, cond, ok_label);
    codegen_once_store_return(s, operand);
    n00b_cg_emit_ret(s, operand);
    n00b_cg_label_here(s, ok_label);

    const char *unwrap_name
        = is_option ? "n00b_builtin_option_unwrap" : "n00b_builtin_result_unwrap";
    void *unwrap_addr
        = is_option ? (void *)n00b_builtin_option_unwrap : (void *)n00b_builtin_result_unwrap;

    n00b_cg_import_func(s,
                        unwrap_name,
                        unwrap_addr,
                        .ret         = N00B_CG_I64,
                        .param_types = check_pt,
                        .n_params    = 1);

    n00b_cg_val_t inner = n00b_cg_emit_call(s, unwrap_name, &operand, 1, .ret = N00B_CG_I64);
    n00b_cg_type_tag_t inner_type = n00b_codegen_node_type(s, cf->self);

    if (inner_type != N00B_CG_VOID) {
        inner.type_tag = inner_type;
    }

    return inner;
}

// ============================================================================
// CF_CALL: function call via control flow label
// ============================================================================

// Check if a callee node is a method call (has a '.' token child).
// If so, return the receiver subtree and the method name.
static bool
is_method_call(n00b_parse_tree_t  *callee,
               n00b_parse_tree_t **receiver_out,
               const char        **method_out)
{
    if (!callee || n00b_pt_is_token(callee)) {
        return false;
    }

    // Look for a '.' token among children. If found, the child before
    // it is the receiver and the token after it is the method name.
    size_t nc        = n00b_pt_num_children(callee);
    bool   found_dot = false;

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(callee, i);

        if (n00b_pt_is_token(child)) {
            const char *text = n00b_pt_token_text(child);
            size_t      len  = n00b_pt_token_text_len(child);

            if (text && len == 1 && text[0] == '.') {
                found_dot = true;
                continue;
            }

            // Token after '.' is the method name.
            if (found_dot && text && len > 0) {
                char *buf = n00b_alloc_array(char, len + 1);
                memcpy(buf, text, len);
                buf[len]    = '\0';
                *method_out = buf;
            }
        }
        else if (!found_dot) {
            *receiver_out = child;
        }
    }

    return found_dot && *receiver_out && *method_out;
}

static n00b_cg_val_t
codegen_call_cf(n00b_cg_session_t *s, n00b_cf_label_t *cf)
{
    // CF_CALL has: cond = callee node, then_body = args node.
    // Check for method call (expr.name) vs plain function call (name).
    const char        *func_name       = NULL;
    n00b_parse_tree_t *receiver        = NULL;
    const char        *method          = NULL;
    const char        *method_mir_name = NULL;
    n00b_cg_val_t      recv_val        = N00B_CG_VOID_VAL;

    if (cf->cond && is_method_call(cf->cond, &receiver, &method)) {
        recv_val = codegen_walk(s, receiver);
        if (s->has_codegen_errors) {
            return N00B_CG_VOID_VAL;
        }
        func_name       = method;
        method_mir_name = codegen_class_method_mir_name(s, receiver, method);
    }
    else if (cf->cond) {
        n00b_parse_tree_t *name_tok = n00b_pt_first_token(cf->cond);

        if (name_tok) {
            const char *raw = n00b_pt_token_text(name_tok);
            size_t      len = n00b_pt_token_text_len(name_tok);

            if (raw && len > 0) {
                char *buf = n00b_alloc_array(char, len + 1);
                memcpy(buf, raw, len);
                buf[len]  = '\0';
                func_name = buf;
            }
        }
    }

    if (!func_name) {
        return codegen_children_default(s, cf->self);
    }

    // Collect arguments from the args node.
    // For method calls, the receiver is the implicit first argument.
    n00b_cg_val_t args[32];
    int32_t       n_args = 0;

    if (recv_val.kind != N00B_CG_VAL_VOID) {
        args[n_args++] = recv_val;
    }

    codegen_call_actual_t actuals[32];
    int32_t               n_actuals = 0;
    codegen_collect_call_actuals(s, cf->then_body, actuals, 32, &n_actuals);

    if (s->has_codegen_errors) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_val_t call_args[32];
    int32_t       n_call_args = 0;

    const char *bind_func_name = method_mir_name ? method_mir_name : func_name;

    if (!codegen_bind_call_actuals(s,
                                   cf->then_body ? cf->then_body : cf->self,
                                   bind_func_name,
                                   actuals,
                                   n_actuals,
                                   call_args,
                                   &n_call_args)) {
        return N00B_CG_VOID_VAL;
    }

    for (int32_t i = 0; i < n_call_args && n_args < 32; i++) {
        args[n_args++] = call_args[i];
    }

    // Check for built-in functions before falling through to generic
    // MIR call emission.
    n00b_cg_val_t        builtin_result;
    n00b_cg_type_tag_t   ret_type = n00b_codegen_node_type(s, cf->self);
    codegen_func_meta_t *meta     = codegen_lookup_func_meta(s, bind_func_name);

    if (meta) {
        ret_type = meta->ret_type;
    }

    if (strcmp(func_name, "call") == 0 && n_actuals > 0) {
        codegen_param_meta_t *callback_param
            = codegen_callback_param_meta_for_actual(s, &actuals[0]);

        if (callback_param) {
            ret_type = callback_param->callback_ret_type;

            for (int32_t i = 0; i < callback_param->callback_n_params && (i + 1) < n_args;
                 i++) {
                args[i + 1].type_tag = callback_param->callback_param_types[i];
            }
        }
        else {
            n00b_rt_callback_t *callback = codegen_local_callback_for_actual(s, &actuals[0]);

            if (callback && callback->has_signature) {
                ret_type = callback->ret_type;

                for (int32_t i = 0; i < callback->n_params && (i + 1) < n_args; i++) {
                    args[i + 1].type_tag = callback->param_types[i];
                }
            }
        }
    }

    if (n00b_codegen_builtin_call(s, func_name, args, n_args, ret_type, &builtin_result)) {
        return builtin_result;
    }

    // For method calls, try vtable dispatch (builtin methods).
    if (recv_val.kind != N00B_CG_VAL_VOID) {
        if (n00b_codegen_method_dispatch(s, func_name, args, n_args, &builtin_result)) {
            return builtin_result;
        }
    }

    // For method calls, try class method dispatch (static binding).
    if (recv_val.kind != N00B_CG_VAL_VOID && method_mir_name) {
        // Emit direct call to the mangled MIR function.
        // args[0] is already the receiver (self).
        if (ret_type == N00B_CG_PTR) {
            ret_type = N00B_CG_I64;
        }

        return n00b_cg_emit_call(s, method_mir_name, args, n_args, .ret = ret_type);
    }

    // Check for class constructor call.
    // Only for classes (scope_tag == "class"), not tuples.
    {
        n00b_annot_result_t *ar = current_annot(s);

        if (ar && ar->symtab) {
            n00b_string_t    *fn_str = n00b_string_from_cstr(func_name);
            n00b_sym_entry_t *sym
                = n00b_symtab_lookup_any(ar->symtab, n00b_string_empty(), fn_str);

            // Guard: only classes, not tuples.
            bool is_class = sym && sym->exposed_scope && sym->exposed_scope->scope_tag
                         && (sym->exposed_scope->scope_tag->u8_bytes == 5
                             && memcmp(sym->exposed_scope->scope_tag->data, "class", 5) == 0);

            if (is_class) {
                if (!sym->class_layout) {
                    sym->class_layout = compute_class_layout(s, sym->exposed_scope);
                }

                n00b_class_layout_t *layout = sym->class_layout;

                // Allocate instance.
                n00b_cg_type_tag_t alloc_pt[] = {N00B_CG_I64};
                n00b_cg_import_func(s,
                                    "n00b_builtin_obj_alloc",
                                    (void *)n00b_builtin_obj_alloc,
                                    .ret         = N00B_CG_I64,
                                    .param_types = alloc_pt,
                                    .n_params    = 1);
                n00b_cg_val_t size_arg = _n00b_cg_const_i64(s, (int64_t)layout->instance_size);
                n00b_cg_val_t obj      = n00b_cg_emit_call(s,
                                                      "n00b_builtin_obj_alloc",
                                                      &size_arg,
                                                      1,
                                                      .ret = N00B_CG_I64);
                obj.type_tag           = N00B_CG_PTR;

                if (layout->has_init) {
                    // Call init: ClassName$init(obj, arg0, arg1, ...)
                    // Find the init method's MIR name.
                    const char *init_mir = NULL;

                    for (uint32_t mi = 0; mi < layout->n_methods; mi++) {
                        if (strcmp(layout->method_names[mi], "init") == 0) {
                            init_mir = layout->method_mir_names[mi];
                            break;
                        }
                    }

                    if (init_mir) {
                        // Build args: [obj, original_args...]
                        n00b_cg_val_t init_args[n_args + 1];
                        init_args[0] = obj;

                        for (int32_t i = 0; i < n_args; i++) {
                            init_args[i + 1] = args[i];
                        }

                        n00b_cg_emit_call(s,
                                          init_mir,
                                          init_args,
                                          n_args + 1,
                                          .ret = N00B_CG_I64);
                    }
                }
                else {
                    // No init — auto-assign positional args to fields.
                    n00b_cg_type_tag_t set_pt[] = {N00B_CG_I64, N00B_CG_I64, N00B_CG_I64};
                    n00b_cg_import_func(s,
                                        "n00b_builtin_field_set",
                                        (void *)n00b_builtin_field_set,
                                        .ret         = N00B_CG_VOID,
                                        .param_types = set_pt,
                                        .n_params    = 3);

                    for (int32_t i = 0; i < n_args && (uint32_t)i < layout->n_fields; i++) {
                        n00b_cg_val_t offset_arg
                            = _n00b_cg_const_i64(s, (int64_t)layout->field_offsets[i]);
                        n00b_cg_val_t set_args[] = {obj, offset_arg, args[i]};
                        n00b_cg_emit_call(s,
                                          "n00b_builtin_field_set",
                                          set_args,
                                          3,
                                          .ret = N00B_CG_VOID);
                    }
                }

                return obj;
            }
        }
    }

    meta = codegen_lookup_func_meta(s, func_name);

    if (meta) {
        ret_type = meta->ret_type;
    }

    // If the node type is unresolved (mapped to PTR for Var types),
    // default to I64 since MIR call protos need a concrete type and
    // I64 is the most common return type for user functions.
    if (ret_type == N00B_CG_PTR) {
        ret_type = N00B_CG_I64;
    }

    if (codegen_reject_private_cross_module_call(s, cf->self, func_name)) {
        return N00B_CG_VOID_VAL;
    }

    return n00b_cg_emit_call(s, func_name, args, n_args, .ret = ret_type);
}

// ============================================================================
// Switch codegen
// ============================================================================

static n00b_parse_tree_t *
switch_first_nt_child(n00b_parse_tree_t *node, const char *nt_name)
{
    n00b_parse_tree_t *matches[1] = {NULL};

    if (n00b_pt_collect_nt_deep(node, nt_name, matches, 1) == 1) {
        return matches[0];
    }

    return NULL;
}

static void
codegen_switch_case_expr_item(n00b_cg_session_t *s,
                              n00b_parse_tree_t *item,
                              n00b_cg_val_t      switch_val,
                              n00b_cg_val_t      match_label)
{
    n00b_parse_tree_t *exprs[2] = {NULL, NULL};
    int                n_exprs  = 0;
    bool               is_range = false;
    size_t             nc       = n00b_pt_num_children(item);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(item, i);

        if (n00b_pt_is_nt(child, "expression") && n_exprs < 2) {
            exprs[n_exprs++] = child;
        }
        else if (n00b_pt_is_nt(child, "range-sep")) {
            is_range = true;
        }
    }

    if (is_range && n_exprs == 2) {
        n00b_cg_val_t low  = codegen_walk(s, exprs[0]);
        n00b_cg_val_t high = codegen_walk(s, exprs[1]);
        n00b_cg_val_t ge   = n00b_cg_emit_ge(s, switch_val, low);
        n00b_cg_val_t le   = n00b_cg_emit_le(s, switch_val, high);
        n00b_cg_val_t both = n00b_cg_emit_and(s, ge, le);
        n00b_cg_emit_bt(s, both, match_label);
    }
    else if (n_exprs == 1) {
        n00b_cg_val_t val = codegen_walk(s, exprs[0]);
        n00b_cg_val_t eq  = n00b_cg_emit_eq(s, switch_val, val);
        n00b_cg_emit_bt(s, eq, match_label);
    }
}

static void
codegen_switch_case_expr_list(n00b_cg_session_t *s,
                              n00b_parse_tree_t *expr_list,
                              n00b_cg_val_t      switch_val,
                              n00b_cg_val_t      match_label)
{
    if (!expr_list) {
        return;
    }

    if (n00b_pt_is_nt(expr_list, "case-expr-item")) {
        codegen_switch_case_expr_item(s, expr_list, switch_val, match_label);
        return;
    }

    size_t nc = n00b_pt_num_children(expr_list);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(expr_list, i);

        if (n00b_pt_is_nt(child, "case-expr-item") || n00b_pt_is_nt(child, "case-expr-list")) {
            codegen_switch_case_expr_list(s, child, switch_val, match_label);
        }
    }
}

static bool
type_name_eq(const char *name, size_t name_len, const char *want)
{
    size_t want_len = strlen(want);

    return name && name_len == want_len && memcmp(name, want, want_len) == 0;
}

static bool
cg_tag_matches_type_name(n00b_cg_type_tag_t tag, const char *name, size_t name_len)
{
    switch (tag) {
    case N00B_CG_I8:
        return type_name_eq(name, name_len, "i8");
    case N00B_CG_I16:
        return type_name_eq(name, name_len, "i16");
    case N00B_CG_I32:
        return type_name_eq(name, name_len, "i32");
    case N00B_CG_I64:
        return type_name_eq(name, name_len, "int") || type_name_eq(name, name_len, "i64");
    case N00B_CG_U8:
        return type_name_eq(name, name_len, "u8");
    case N00B_CG_U16:
        return type_name_eq(name, name_len, "u16");
    case N00B_CG_U32:
        return type_name_eq(name, name_len, "u32");
    case N00B_CG_U64:
        return type_name_eq(name, name_len, "u64");
    case N00B_CG_F32:
        return type_name_eq(name, name_len, "f32");
    case N00B_CG_F64:
        return type_name_eq(name, name_len, "float") || type_name_eq(name, name_len, "f64");
    case N00B_CG_STRING:
        return type_name_eq(name, name_len, "string");
    case N00B_CG_LIST:
        return type_name_eq(name, name_len, "list");
    case N00B_CG_DICT:
        return type_name_eq(name, name_len, "dict");
    case N00B_CG_SET:
        return type_name_eq(name, name_len, "set");
    case N00B_CG_RESULT:
        return type_name_eq(name, name_len, "result");
    case N00B_CG_OPTION:
        return type_name_eq(name, name_len, "option") || type_name_eq(name, name_len, "maybe");
    case N00B_CG_FUNC:
        return type_name_eq(name, name_len, "func");
    case N00B_CG_NIL:
        return type_name_eq(name, name_len, "nil");
    case N00B_CG_BOOL:
        return type_name_eq(name, name_len, "bool");
    case N00B_CG_VOID:
        return type_name_eq(name, name_len, "void");
    case N00B_CG_PTR:
        return type_name_eq(name, name_len, "ptr");
    }

    return false;
}

static bool
tc_type_matches_type_name(n00b_cg_session_t *s,
                          n00b_tc_type_t    *type,
                          n00b_cg_type_tag_t tag,
                          const char        *name,
                          size_t             name_len)
{
    if (type) {
        type = n00b_tc_find(type);

        if (n00b_variant_is_type(type->kind, n00b_tc_prim_t)) {
            n00b_tc_prim_t prim = n00b_variant_get(type->kind, n00b_tc_prim_t);

            if (prim.name && prim.name->u8_bytes == name_len
                && memcmp(prim.name->data, name, name_len) == 0) {
                return true;
            }

            n00b_cg_type_tag_t prim_tag = s->type_map ? s->type_map(s, type) : tag;
            return cg_tag_matches_type_name(prim_tag, name, name_len);
        }

        if (n00b_variant_is_type(type->kind, n00b_tc_param_t)) {
            n00b_tc_param_t param = n00b_variant_get(type->kind, n00b_tc_param_t);

            if (param.name && param.name->u8_bytes == name_len
                && memcmp(param.name->data, name, name_len) == 0) {
                return true;
            }
        }
    }

    return cg_tag_matches_type_name(tag, name, name_len);
}

static bool
typeof_case_matches(n00b_cg_session_t *s,
                    n00b_parse_tree_t *case_block,
                    n00b_tc_type_t    *cond_type,
                    n00b_cg_type_tag_t cond_tag)
{
    n00b_parse_tree_t *type_list = switch_first_nt_child(case_block, "type-spec-list");
    n00b_parse_tree_t *types[32];
    int                ntypes = n00b_pt_collect_nt_deep(type_list, "type-spec", types, 32);

    for (int i = 0; i < ntypes; i++) {
        n00b_parse_tree_t *tok = n00b_pt_first_token(types[i]);

        if (!tok) {
            continue;
        }

        const char *name = n00b_pt_token_text(tok);
        size_t      len  = n00b_pt_token_text_len(tok);

        if (tc_type_matches_type_name(s, cond_type, cond_tag, name, len)) {
            return true;
        }
    }

    return false;
}

static void
codegen_typeof_case_body(n00b_cg_session_t *s, n00b_parse_tree_t *case_block)
{
    n00b_parse_tree_t *body = switch_first_nt_child(case_block, "case-body");

    if (!body) {
        body = switch_first_nt_child(case_block, "body");
    }

    if (body) {
        if (codegen_tree_contains_statement_yield(body)) {
            codegen_error(s, body, "CG022", "typeof case body cannot yield a value");
            return;
        }

        codegen_walk(s, body);
    }
}

static n00b_cg_val_t
codegen_typeof(n00b_cg_session_t *s, n00b_cf_label_t *cf)
{
    n00b_tc_type_t    *cond_type = n00b_codegen_node_tc_type(s, cf->cond);
    n00b_cg_type_tag_t cond_tag  = n00b_codegen_node_type(s, cf->cond);
    n00b_parse_tree_t *case_blocks[64];
    int nblocks = n00b_pt_collect_nt_deep(cf->then_body, "typeof-case-block", case_blocks, 64);

    for (int i = 0; i < nblocks; i++) {
        if (typeof_case_matches(s, case_blocks[i], cond_type, cond_tag)) {
            codegen_typeof_case_body(s, case_blocks[i]);
            return N00B_CG_VOID_VAL;
        }
    }

    n00b_parse_tree_t *case_else = switch_first_nt_child(cf->then_body, "case-else");

    if (case_else) {
        codegen_typeof_case_body(s, case_else);
    }

    return N00B_CG_VOID_VAL;
}

typedef struct {
    n00b_cg_val_t      result;
    n00b_cg_type_tag_t result_type;
    bool               have_result;
    bool               all_yield;
} codegen_switch_value_state_t;

static n00b_parse_tree_t *
codegen_switch_case_body(n00b_parse_tree_t *case_block)
{
    const char *body_names[] = {
        "case-body",
        "body",
        "yielding-case-body",
        "yielding-body",
    };

    return codegen_first_direct_nt_child_any(case_block,
                                             body_names,
                                             (int)(sizeof(body_names) / sizeof(body_names[0])));
}

static n00b_parse_tree_t *
codegen_switch_branch_case_block(n00b_parse_tree_t *branch_list, const char *case_block_name)
{
    n00b_parse_tree_t *case_block = codegen_first_direct_nt_child(branch_list, case_block_name);

    if (case_block) {
        return case_block;
    }

    n00b_parse_tree_t *prefix
        = codegen_first_direct_nt_child(branch_list, "switch-value-case-prefix");

    if (!prefix) {
        return NULL;
    }

    return codegen_first_direct_nt_child(prefix, case_block_name);
}

static void
codegen_switch_record_arm(n00b_cg_session_t            *s,
                          n00b_parse_tree_t            *site,
                          n00b_cg_val_t                 value,
                          bool                          arm_yielded,
                          codegen_switch_value_state_t *state)
{
    if (!arm_yielded) {
        state->all_yield = false;
        return;
    }

    codegen_store_yield_value(s,
                              site,
                              value,
                              &state->result,
                              &state->result_type,
                              &state->have_result);
}

static void
codegen_switch_case_block(n00b_cg_session_t            *s,
                          n00b_parse_tree_t            *case_block,
                          n00b_cg_val_t                 switch_val,
                          n00b_cg_val_t                 end_label,
                          n00b_cg_val_t                 next_label,
                          codegen_switch_value_state_t *state)
{
    n00b_parse_tree_t *expr_list = codegen_first_direct_nt_child(case_block, "case-expr-list");
    n00b_parse_tree_t *body      = codegen_switch_case_body(case_block);

    n00b_cg_val_t match_label = n00b_cg_label_new(s);

    if (expr_list) {
        codegen_switch_case_expr_list(s, expr_list, switch_val, match_label);
    }

    // No match — jump to next case.
    n00b_cg_emit_jmp(s, next_label);

    // Match: emit body, then jump to end.
    n00b_cg_label_here(s, match_label);

    if (body) {
        bool          yielded = false;
        n00b_cg_val_t value   = codegen_block_value(s, body, &yielded);
        codegen_switch_record_arm(s, body, value, yielded, state);
    }
    else {
        state->all_yield = false;
    }

    n00b_cg_emit_jmp(s, end_label);
}

static void
codegen_switch_branch_list(n00b_cg_session_t            *s,
                           n00b_parse_tree_t            *branch_list,
                           n00b_cg_val_t                 switch_val,
                           n00b_cg_val_t                 end_label,
                           const char                   *case_block_name,
                           const char                   *branch_list_name,
                           codegen_switch_value_state_t *state)
{
    n00b_parse_tree_t *case_block
        = codegen_switch_branch_case_block(branch_list, case_block_name);
    n00b_parse_tree_t *next_branch
        = codegen_first_direct_nt_child(branch_list, branch_list_name);

    n00b_cg_val_t next_label = n00b_cg_label_new(s);

    if (case_block) {
        codegen_switch_case_block(s, case_block, switch_val, end_label, next_label, state);
    }

    n00b_cg_label_here(s, next_label);

    if (next_branch) {
        codegen_switch_branch_list(s,
                                   next_branch,
                                   switch_val,
                                   end_label,
                                   case_block_name,
                                   branch_list_name,
                                   state);
    }
}

static n00b_cg_val_t
codegen_switch_common(n00b_cg_session_t *s, n00b_cf_label_t *cf, bool require_value)
{
    if (cf->then_body && n00b_pt_is_nt(cf->then_body, "typeof-cases")) {
        return codegen_typeof(s, cf);
    }

    // @switch($1, $3): cond = switch expression, then_body = <switch-cases>
    n00b_cg_val_t switch_val = N00B_CG_VOID_VAL;

    if (cf->cond) {
        switch_val = codegen_walk(s, cf->cond);
    }

    if (s->has_codegen_errors || switch_val.kind == N00B_CG_VAL_VOID) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_val_t                end_label = n00b_cg_label_new(s);
    codegen_switch_value_state_t state     = {
            .result      = N00B_CG_VOID_VAL,
            .result_type = N00B_CG_VOID,
            .all_yield   = true,
    };

    if (cf->then_body) {
        bool        value_switch = n00b_pt_is_nt(cf->then_body, "switch-value-cases");
        const char *branch_list_name
            = value_switch ? "switch-value-branch-list" : "branch-list";
        const char *case_block_name
            = value_switch ? "switch-value-case-block" : "switch-case-block";
        const char *else_name = value_switch ? "switch-value-else" : "case-else";

        n00b_parse_tree_t *branch_list
            = codegen_first_direct_nt_child(cf->then_body, branch_list_name);
        n00b_parse_tree_t *case_else = codegen_first_direct_nt_child(cf->then_body, else_name);

        if (branch_list) {
            codegen_switch_branch_list(s,
                                       branch_list,
                                       switch_val,
                                       end_label,
                                       case_block_name,
                                       branch_list_name,
                                       &state);
        }
        else {
            state.all_yield = false;
        }

        if (case_else) {
            bool               yielded = false;
            n00b_parse_tree_t *body    = codegen_switch_case_body(case_else);
            n00b_cg_val_t      value   = codegen_block_value(s, body, &yielded);
            codegen_switch_record_arm(s, body ? body : case_else, value, yielded, &state);
        }
        else {
            state.all_yield = false;
        }
    }
    else {
        state.all_yield = false;
    }

    n00b_cg_label_here(s, end_label);

    if (state.all_yield && state.have_result && !s->has_codegen_errors) {
        return state.result;
    }

    if (require_value && !s->has_codegen_errors) {
        codegen_error(s,
                      cf->self,
                      "CG022",
                      "value-producing switch does not yield on every path");
    }

    return N00B_CG_VOID_VAL;
}

static n00b_cg_val_t
codegen_switch(n00b_cg_session_t *s, n00b_cf_label_t *cf)
{
    return codegen_switch_common(s, cf, false);
}

static n00b_cg_val_t
codegen_switch_value_expr(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    n00b_cf_label_t *cf = n00b_codegen_cf_label(s, node);

    if (!cf) {
        return codegen_children_default(s, node);
    }

    bool          saved_reject = s->reject_unconsumed_yield;
    s->reject_unconsumed_yield = false;
    n00b_cg_val_t result       = codegen_switch_common(s, cf, true);
    s->reject_unconsumed_yield = saved_reject;
    return result;
}

// ============================================================================
// Named tuple handler
// ============================================================================

typedef struct {
    n00b_parse_tree_t **items;
    int                 count;
    int                 cap;
} codegen_expr_vec_t;

static void
codegen_expr_vec_push(codegen_expr_vec_t *vec, n00b_parse_tree_t *node)
{
    if (!vec || !node) {
        return;
    }

    if (vec->count >= vec->cap) {
        int                 new_cap   = vec->cap ? vec->cap * 2 : 32;
        n00b_parse_tree_t **new_items = n00b_alloc_array(n00b_parse_tree_t *, (size_t)new_cap);

        if (vec->items && vec->count > 0) {
            memcpy(new_items, vec->items, sizeof(n00b_parse_tree_t *) * (size_t)vec->count);
        }

        vec->items = new_items;
        vec->cap   = new_cap;
    }

    vec->items[vec->count++] = node;
}

static void
collect_list_literal_exprs(n00b_parse_tree_t *node, codegen_expr_vec_t *exprs)
{
    if (!node || !exprs || n00b_pt_is_token(node)) {
        return;
    }

    if (n00b_pt_is_nt(node, "expression")) {
        codegen_expr_vec_push(exprs, node);
        return;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        collect_list_literal_exprs(n00b_pt_get_child(node, i), exprs);
    }
}

static n00b_cg_val_t
codegen_list(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    n00b_cg_import_func(s,
                        "n00b_builtin_list_new",
                        (void *)n00b_builtin_list_new,
                        .ret = N00B_CG_I64);

    n00b_cg_val_t list
        = n00b_cg_emit_call(s, "n00b_builtin_list_new", NULL, 0, .ret = N00B_CG_I64);
    list.type_tag = N00B_CG_LIST;

    codegen_expr_vec_t exprs = {0};
    collect_list_literal_exprs(node, &exprs);

    if (exprs.count == 0) {
        return list;
    }

    n00b_cg_type_tag_t push_pt[] = {N00B_CG_I64, N00B_CG_I64, N00B_CG_I64};
    n00b_cg_import_func(s,
                        "n00b_builtin_list_push_value",
                        (void *)n00b_builtin_list_push_value,
                        .ret         = N00B_CG_VOID,
                        .param_types = push_pt,
                        .n_params    = 3);

    for (int i = 0; i < exprs.count; i++) {
        n00b_cg_val_t value = codegen_walk(s, exprs.items[i]);

        if (value.kind == N00B_CG_VAL_VOID) {
            continue;
        }

        n00b_cg_val_t value_tag = _n00b_cg_const_i64(s, (int64_t)value.type_tag);
        n00b_cg_val_t args[]    = {list, value, value_tag};
        n00b_cg_emit_call(s, "n00b_builtin_list_push_value", args, 3, .ret = N00B_CG_VOID);
    }

    return list;
}

static void
collect_dict_entries(n00b_parse_tree_t *node, codegen_expr_vec_t *entries)
{
    if (!node || !entries || n00b_pt_is_token(node)) {
        return;
    }

    if (n00b_pt_is_nt(node, "dict-entry")) {
        codegen_expr_vec_push(entries, node);
        return;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        collect_dict_entries(n00b_pt_get_child(node, i), entries);
    }
}

static void
collect_set_literal_exprs(n00b_parse_tree_t *node, codegen_expr_vec_t *exprs)
{
    if (!node || !exprs || n00b_pt_is_token(node)) {
        return;
    }

    if (n00b_pt_is_nt(node, "expression")) {
        codegen_expr_vec_push(exprs, node);
        return;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        collect_set_literal_exprs(n00b_pt_get_child(node, i), exprs);
    }
}

static n00b_cg_val_t
codegen_set_literal(n00b_cg_session_t *s,
                    n00b_parse_tree_t *node,
                    n00b_parse_tree_t *set_entries)
{
    n00b_cg_import_func(s,
                        "n00b_builtin_set_new",
                        (void *)n00b_builtin_set_new,
                        .ret = N00B_CG_I64);

    n00b_cg_val_t set
        = n00b_cg_emit_call(s, "n00b_builtin_set_new", NULL, 0, .ret = N00B_CG_I64);
    set.type_tag = N00B_CG_SET;

    if (!set_entries) {
        return set;
    }

    codegen_expr_vec_t exprs = {0};
    collect_set_literal_exprs(set_entries, &exprs);

    if (exprs.count == 0) {
        return set;
    }

    n00b_cg_type_tag_t add_pt[] = {N00B_CG_SET, N00B_CG_I64, N00B_CG_I64};
    n00b_cg_import_func(s,
                        "n00b_builtin_set_add_value",
                        (void *)n00b_builtin_set_add_value,
                        .ret         = N00B_CG_VOID,
                        .param_types = add_pt,
                        .n_params    = 3);

    for (int i = 0; i < exprs.count; i++) {
        n00b_cg_val_t value = codegen_walk(s, exprs.items[i]);

        if (value.kind == N00B_CG_VAL_VOID) {
            continue;
        }

        n00b_cg_val_t value_tag = _n00b_cg_const_i64(s, (int64_t)value.type_tag);
        n00b_cg_val_t args[]    = {set, value, value_tag};
        n00b_cg_emit_call(s, "n00b_builtin_set_add_value", args, 3, .ret = N00B_CG_VOID);
    }

    return set;
}

static bool
dict_entry_exprs(n00b_parse_tree_t  *entry,
                 n00b_parse_tree_t **key_out,
                 n00b_parse_tree_t **value_out)
{
    n00b_parse_tree_t *exprs[2] = {NULL, NULL};
    int                nexprs   = 0;
    size_t             nc       = n00b_pt_num_children(entry);

    for (size_t i = 0; i < nc && nexprs < 2; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(entry, i);

        if (child && n00b_pt_is_nt(child, "expression")) {
            exprs[nexprs++] = child;
        }
    }

    if (nexprs != 2) {
        return false;
    }

    *key_out   = exprs[0];
    *value_out = exprs[1];
    return true;
}

static n00b_cg_val_t
codegen_dict_or_set(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    codegen_expr_vec_t entries        = {0};
    n00b_parse_tree_t *set_entries[1] = {NULL};
    bool has_set_entries = n00b_pt_collect_nt_deep(node, "set-entries", set_entries, 1) > 0;

    collect_dict_entries(node, &entries);

    if (has_set_entries) {
        return codegen_set_literal(s, node, set_entries[0]);
    }

    if (entries.count == 0 && n00b_codegen_node_type(s, node) == N00B_CG_SET) {
        return codegen_set_literal(s, node, NULL);
    }

    if (entries.count == 0 && n00b_codegen_node_type(s, node) != N00B_CG_DICT) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_import_func(s,
                        "n00b_builtin_dict_new",
                        (void *)n00b_builtin_dict_new,
                        .ret = N00B_CG_I64);

    n00b_cg_val_t dict
        = n00b_cg_emit_call(s, "n00b_builtin_dict_new", NULL, 0, .ret = N00B_CG_I64);
    dict.type_tag = N00B_CG_DICT;

    if (entries.count == 0) {
        return dict;
    }

    n00b_cg_type_tag_t put_pt[]
        = {N00B_CG_DICT, N00B_CG_I64, N00B_CG_I64, N00B_CG_I64, N00B_CG_I64};
    n00b_cg_import_func(s,
                        "n00b_builtin_dict_put_value",
                        (void *)n00b_builtin_dict_put_value,
                        .ret         = N00B_CG_VOID,
                        .param_types = put_pt,
                        .n_params    = 5);

    for (int i = 0; i < entries.count; i++) {
        n00b_parse_tree_t *key_node = NULL;
        n00b_parse_tree_t *val_node = NULL;

        if (!dict_entry_exprs(entries.items[i], &key_node, &val_node)) {
            continue;
        }

        n00b_cg_val_t key = codegen_walk(s, key_node);
        n00b_cg_val_t val = codegen_walk(s, val_node);

        if (key.kind == N00B_CG_VAL_VOID || val.kind == N00B_CG_VAL_VOID) {
            continue;
        }

        n00b_cg_val_t key_tag = _n00b_cg_const_i64(s, (int64_t)key.type_tag);
        n00b_cg_val_t val_tag = _n00b_cg_const_i64(s, (int64_t)val.type_tag);
        n00b_cg_val_t args[]  = {dict, key, key_tag, val, val_tag};
        n00b_cg_emit_call(s, "n00b_builtin_dict_put_value", args, 5, .ret = N00B_CG_VOID);
    }

    return dict;
}

static n00b_cg_val_t
codegen_tuple(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    // Check if this is a named tuple (has named-field-list child)
    // or a parenthesized expression (just walk children).
    n00b_parse_tree_t *field_list = NULL;
    size_t             nc         = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (child && n00b_pt_is_nt(child, "named-field-list")) {
            field_list = child;
            break;
        }
    }

    if (!field_list) {
        // Parenthesized expression or positional tuple — walk children.
        return codegen_children_default(s, node);
    }

    // Named tuple: collect field names and values via DFS through
    // named-field-list -> named-field nodes.
    const char   *names[32];
    n00b_cg_val_t values[32];
    int32_t       n_fields = 0;

    n00b_parse_tree_t *stack[64];
    int                sp = 0;

    stack[sp++] = field_list;

    while (sp > 0 && n_fields < 32) {
        n00b_parse_tree_t *cur = stack[--sp];

        if (!cur || n00b_pt_is_token(cur)) {
            continue;
        }

        if (n00b_pt_is_nt(cur, "named-field")) {
            // named-field: IDENTIFIER ":" expression
            const char   *fname     = NULL;
            size_t        fname_len = 0;
            n00b_cg_val_t fval      = N00B_CG_VOID_VAL;

            size_t fnc        = n00b_pt_num_children(cur);
            bool   past_colon = false;

            for (size_t j = 0; j < fnc; j++) {
                n00b_parse_tree_t *fc = n00b_pt_get_child(cur, j);

                if (n00b_pt_is_token(fc)) {
                    const char *t  = n00b_pt_token_text(fc);
                    size_t      tl = n00b_pt_token_text_len(fc);

                    if (tl == 1 && t[0] == ':') {
                        past_colon = true;
                    }
                    else if (!past_colon && !fname) {
                        fname     = t;
                        fname_len = tl;
                    }
                }
                else if (past_colon) {
                    fval = codegen_walk(s, fc);
                }
            }

            if (fname && fname_len > 0 && fval.kind != N00B_CG_VAL_VOID) {
                char *name_buf = n00b_alloc_array(char, fname_len + 1);
                memcpy(name_buf, fname, fname_len);
                name_buf[fname_len] = '\0';
                names[n_fields]     = name_buf;
                values[n_fields]    = fval;
                n_fields++;
            }

            continue;
        }

        // Push children in reverse for L-to-R order.
        size_t cnc = n00b_pt_num_children(cur);

        for (size_t i = cnc; i > 0; i--) {
            if (sp < 64) {
                stack[sp++] = n00b_pt_get_child(cur, i - 1);
            }
        }
    }

    if (n_fields == 0) {
        return N00B_CG_VOID_VAL;
    }

    // Look up the structural tuple type created by the annotation walk's
    // @record handler. Build the same name it used.
    size_t name_len = 7; // "$$tuple"

    for (int32_t i = 0; i < n_fields; i++) {
        name_len += 1 + strlen(names[i]); // "$" + name
    }

    char *tuple_name = n00b_alloc_array(char, name_len + 1);
    char *p          = tuple_name;

    memcpy(p, "$$tuple", 7);
    p += 7;

    for (int32_t i = 0; i < n_fields; i++) {
        *p++      = '$';
        size_t fl = strlen(names[i]);
        memcpy(p, names[i], fl);
        p += fl;
    }

    *p = '\0';

    n00b_annot_result_t *ar        = current_annot(s);
    n00b_sym_entry_t    *tuple_sym = NULL;

    if (ar && ar->symtab) {
        n00b_string_t *tname = n00b_string_from_cstr(tuple_name);
        tuple_sym            = n00b_symtab_lookup_any(ar->symtab, n00b_string_empty(), tname);

        // Compute field layout if not done yet.
        if (tuple_sym && tuple_sym->exposed_scope && !tuple_sym->class_layout) {
            tuple_sym->class_layout = compute_class_layout(s, tuple_sym->exposed_scope);
        }
    }

    n00b_class_layout_t *layout = tuple_sym ? tuple_sym->class_layout : NULL;
    int64_t instance_size = layout ? (int64_t)layout->instance_size : (int64_t)(n_fields * 8);

    n00b_cg_type_tag_t alloc_pt[] = {N00B_CG_I64};
    n00b_cg_import_func(s,
                        "n00b_builtin_obj_alloc",
                        (void *)n00b_builtin_obj_alloc,
                        .ret         = N00B_CG_I64,
                        .param_types = alloc_pt,
                        .n_params    = 1);
    n00b_cg_val_t size_arg = _n00b_cg_const_i64(s, instance_size);
    n00b_cg_val_t obj
        = n00b_cg_emit_call(s, "n00b_builtin_obj_alloc", &size_arg, 1, .ret = N00B_CG_I64);
    obj.type_tag = N00B_CG_PTR;
    obj.aux      = (uint64_t)(uintptr_t)layout;

    n00b_cg_type_tag_t set_pt[] = {N00B_CG_I64, N00B_CG_I64, N00B_CG_I64};
    n00b_cg_import_func(s,
                        "n00b_builtin_field_set",
                        (void *)n00b_builtin_field_set,
                        .ret         = N00B_CG_VOID,
                        .param_types = set_pt,
                        .n_params    = 3);

    for (int32_t i = 0; i < n_fields; i++) {
        int64_t       offset = layout ? (int64_t)layout->field_offsets[i] : (int64_t)(i * 8);
        n00b_cg_val_t offset_arg = _n00b_cg_const_i64(s, offset);
        n00b_cg_val_t set_args[] = {obj, offset_arg, values[i]};
        n00b_cg_emit_call(s, "n00b_builtin_field_set", set_args, 3, .ret = N00B_CG_VOID);
    }

    return obj;
}

// ============================================================================
// Class declaration handler
// ============================================================================

// WP-B: a field holds a GC pointer iff its codegen type tag is a reference
// type. I*/U*/F*/BOOL are inline values; FUNC is a code pointer (not GC heap);
// NIL/VOID carry no live pointer.
static inline bool
cg_tag_is_gc_pointer(n00b_cg_type_tag_t tag)
{
    switch (tag) {
    case N00B_CG_STRING:
    case N00B_CG_LIST:
    case N00B_CG_DICT:
    case N00B_CG_SET:
    case N00B_CG_RESULT:
    case N00B_CG_OPTION:
    case N00B_CG_PTR:
        return true;
    default:
        return false;
    }
}

// Compute field layout for a class from its exposed scope.
// All fields are 8 bytes (uint64_t) for the interpreter.
static n00b_class_layout_t *
compute_class_layout(n00b_cg_session_t *s, n00b_scope_t *scope)
{
    // Count fields. Skip type entries, and the class's own var entry
    // (which has exposed_scope set or matches the scope name).
    int32_t n_fields = 0;

    n00b_sym_entry_t *e;
    for (e = scope->first_in_scope; e; e = e->next_in_scope) {
        if (e->kind != N00B_SYM_VARIABLE && e->kind != N00B_SYM_PARAM) {
            continue;
        }

        // Skip the class's own entry (has exposed_scope or name matches scope).
        if (e->exposed_scope) {
            continue;
        }

        if (scope->name && e->name && e->name->u8_bytes == scope->name->u8_bytes
            && memcmp(e->name->data, scope->name->data, e->name->u8_bytes) == 0) {
            continue;
        }

        n_fields++;
    }

    n00b_class_layout_t *layout = n00b_alloc(n00b_class_layout_t);
    layout->n_fields            = (uint32_t)n_fields;
    layout->field_names         = n00b_alloc_array(const char *, (size_t)n_fields);
    layout->field_offsets       = n00b_alloc_array(uint32_t, (size_t)n_fields);

    // Collect fields into a temp array so we can reverse the scope chain
    // order (scope chain is newest-first, we want declaration order).
    n00b_sym_entry_t *field_entries[n_fields];
    int32_t           fe_count = 0;

    for (e = scope->first_in_scope; e; e = e->next_in_scope) {
        if (e->kind != N00B_SYM_VARIABLE && e->kind != N00B_SYM_PARAM) {
            continue;
        }

        if (e->exposed_scope) {
            continue;
        }

        if (scope->name && e->name && e->name->u8_bytes == scope->name->u8_bytes
            && memcmp(e->name->data, scope->name->data, e->name->u8_bytes) == 0) {
            continue;
        }

        field_entries[fe_count++] = e;
    }

    // Reverse to get declaration order.
    for (int32_t i = 0; i < fe_count / 2; i++) {
        n00b_sym_entry_t *tmp           = field_entries[i];
        field_entries[i]                = field_entries[fe_count - 1 - i];
        field_entries[fe_count - 1 - i] = tmp;
    }

    // All fields are 8 bytes, sequentially laid out.
    for (int32_t idx = 0; idx < fe_count; idx++) {
        n00b_sym_entry_t *e    = field_entries[idx];
        char             *name = n00b_alloc_array(char, e->name->u8_bytes + 1);
        memcpy(name, e->name->data, e->name->u8_bytes);
        name[e->name->u8_bytes] = '\0';

        layout->field_names[idx]   = name;
        layout->field_offsets[idx] = (uint32_t)(idx * 8);
    }

    layout->instance_size = (uint32_t)(n_fields * 8);

    // WP-B: build the per-instance GC pointer map from the field types so an
    // instance can be scanned precisely (and marshaled) rather than
    // conservatively. Allocated from the runtime system_pool (hidden + non-GC):
    // the GC reads the descriptor on every collection and the runtime registry
    // (WP-A) holds it untraced, so it must outlive every instance and must not
    // be traced or moved. WP-C registers it and wires n00b_builtin_obj_alloc to
    // pass type_hash; until then nothing reads gc_descriptor, so this changes no
    // allocation behavior.
    if (fe_count > 0 && s->type_map != nullptr) {
        uint64_t ptr_words[fe_count];
        uint64_t n_ptr = 0;

        for (int32_t idx = 0; idx < fe_count; idx++) {
            n00b_sym_entry_t *fe = field_entries[idx];

            if (fe->type_var == nullptr) {
                continue;
            }

            n00b_cg_type_tag_t tag = s->type_map(s, n00b_tc_find(fe->type_var));

            if (cg_tag_is_gc_pointer(tag)) {
                ptr_words[n_ptr++] = (uint64_t)(layout->field_offsets[idx] / 8);
            }
        }

        n00b_allocator_t        *sys  = n00b_system_allocator();
        n00b_gc_struct_layout_t *desc = n00b_alloc(n00b_gc_struct_layout_t,
                                                   .allocator = sys);
        uint64_t                *offs = nullptr;

        if (n_ptr > 0) {
            offs = n00b_alloc_array(uint64_t, n_ptr, .allocator = sys);
            for (uint64_t i = 0; i < n_ptr; i++) {
                offs[i] = ptr_words[i];
            }
        }

        *desc = (n00b_gc_struct_layout_t){
            .stride        = (uint64_t)(layout->instance_size / 8),
            .count         = 0,
            .offset_count  = n_ptr,
            .offsets       = offs,
            .variant_count = 0,
            .variants      = nullptr,
        };
        layout->gc_descriptor = desc;
    }

    // Collect methods (N00B_SYM_FUNCTION with is_method).
    int32_t n_methods = 0;

    for (e = scope->first_in_scope; e; e = e->next_in_scope) {
        if (e->kind == N00B_SYM_FUNCTION && e->is_method) {
            n_methods++;
        }
    }

    if (n_methods > 0) {
        layout->n_methods        = (uint32_t)n_methods;
        layout->method_names     = n00b_alloc_array(const char *, (size_t)n_methods);
        layout->method_mir_names = n00b_alloc_array(const char *, (size_t)n_methods);

        // Get the class name from the scope name for mangling.
        const char *cname     = scope->name ? scope->name->data : "";
        size_t      cname_len = scope->name ? scope->name->u8_bytes : 0;

        int32_t mi = 0;

        for (e = scope->first_in_scope; e; e = e->next_in_scope) {
            if (e->kind != N00B_SYM_FUNCTION || !e->is_method) {
                continue;
            }

            // Unmangled method name.
            char *mname = n00b_alloc_array(char, e->name->u8_bytes + 1);
            memcpy(mname, e->name->data, e->name->u8_bytes);
            mname[e->name->u8_bytes] = '\0';
            layout->method_names[mi] = mname;

            // Mangled MIR name: ClassName$methodName.
            size_t mir_len  = cname_len + 1 + e->name->u8_bytes;
            char  *mir_name = n00b_alloc_array(char, mir_len + 1);
            memcpy(mir_name, cname, cname_len);
            mir_name[cname_len] = '$';
            memcpy(mir_name + cname_len + 1, e->name->data, e->name->u8_bytes);
            mir_name[mir_len]            = '\0';
            layout->method_mir_names[mi] = mir_name;

            if (e->name->u8_bytes == 4 && memcmp(e->name->data, "init", 4) == 0) {
                layout->has_init = true;
            }

            mi++;
        }
    }

    return layout;
}

// Look up a field index by name in a class layout.
static int32_t
layout_field_index(n00b_class_layout_t *layout, const char *name, size_t name_len)
{
    for (uint32_t i = 0; i < layout->n_fields; i++) {
        if (strlen(layout->field_names[i]) == name_len
            && memcmp(layout->field_names[i], name, name_len) == 0) {
            return (int32_t)i;
        }
    }

    return -1;
}

typedef struct n00b_field_lock_entry_t {
    void                           *obj;
    int64_t                         offset;
    struct n00b_field_lock_entry_t *next;
} n00b_field_lock_entry_t;

static n00b_field_lock_entry_t **n00b_field_lock_buckets;
static int64_t                   n00b_field_lock_count;
static int64_t                   n00b_field_lock_bucket_count;
static n00b_rwlock_t            *n00b_field_lock_guard;

static void
n00b_field_lock_guard_read(void)
{
    if (!n00b_field_lock_guard) {
        n00b_field_lock_guard = n00b_data_lock_new();
    }

    n00b_data_read_lock(n00b_field_lock_guard);
}

static void
n00b_field_lock_guard_write(void)
{
    if (!n00b_field_lock_guard) {
        n00b_field_lock_guard = n00b_data_lock_new();
    }

    n00b_data_write_lock(n00b_field_lock_guard);
}

static void
n00b_field_lock_guard_unlock(void)
{
    n00b_data_unlock(n00b_field_lock_guard);
}

static uint64_t
n00b_field_lock_hash(void *obj, int64_t offset)
{
    uint64_t x = (uint64_t)((uintptr_t)obj >> 3) ^ ((uint64_t)offset * 0x9e3779b97f4a7c15ULL);
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    return x;
}

static void
n00b_field_lock_rehash(int64_t new_bucket_count)
{
    n00b_field_lock_entry_t **new_buckets
        = n00b_alloc_array(n00b_field_lock_entry_t *, (size_t)new_bucket_count);

    for (int64_t i = 0; i < n00b_field_lock_bucket_count; i++) {
        n00b_field_lock_entry_t *entry = n00b_field_lock_buckets[i];

        while (entry) {
            n00b_field_lock_entry_t *next = entry->next;
            uint64_t                 bucket
                = n00b_field_lock_hash(entry->obj, entry->offset) % (uint64_t)new_bucket_count;
            entry->next         = new_buckets[bucket];
            new_buckets[bucket] = entry;
            entry               = next;
        }
    }

    n00b_field_lock_buckets      = new_buckets;
    n00b_field_lock_bucket_count = new_bucket_count;
}

static bool
n00b_field_lock_find(void *obj, int64_t offset)
{
    if (!n00b_field_lock_buckets || n00b_field_lock_bucket_count == 0) {
        return false;
    }

    uint64_t bucket
        = n00b_field_lock_hash(obj, offset) % (uint64_t)n00b_field_lock_bucket_count;

    n00b_field_lock_entry_t *entry;
    for (entry = n00b_field_lock_buckets[bucket]; entry;
         entry = entry->next) {
        if (entry->obj == obj && entry->offset == offset) {
            return true;
        }
    }

    return false;
}

static void
n00b_field_lock_insert(void *obj, int64_t offset)
{
    if (!n00b_field_lock_buckets) {
        n00b_field_lock_rehash(64);
    }
    else if (n00b_field_lock_count >= n00b_field_lock_bucket_count * 2) {
        n00b_field_lock_rehash(n00b_field_lock_bucket_count * 2);
    }

    uint64_t bucket
        = n00b_field_lock_hash(obj, offset) % (uint64_t)n00b_field_lock_bucket_count;
    n00b_field_lock_entry_t *entry  = n00b_alloc(n00b_field_lock_entry_t);
    entry->obj                      = obj;
    entry->offset                   = offset;
    entry->next                     = n00b_field_lock_buckets[bucket];
    n00b_field_lock_buckets[bucket] = entry;
    n00b_field_lock_count++;
}

static void
n00b_field_lock_fail(void)
{
    fprintf(stderr, "n00b: attribute is locked\n");
    exit(1);
}

// C runtime: allocate a class instance (zeroed).
static void *
n00b_builtin_obj_alloc(int64_t size)
{
    return n00b_alloc_size(1, (size_t)size);
}

// C runtime: read a field from an object at a byte offset.
static uint64_t
n00b_builtin_field_get(void *obj, int64_t offset)
{
    return *(uint64_t *)((char *)obj + offset);
}

// C runtime: write a field in an object at a byte offset.
static void
n00b_builtin_field_set(void *obj, int64_t offset, uint64_t value)
{
    if (n00b_field_lock_count == 0) {
        *(uint64_t *)((char *)obj + offset) = value;
        return;
    }

    n00b_field_lock_guard_read();

    if (n00b_field_lock_find(obj, offset)) {
        n00b_field_lock_guard_unlock();
        n00b_field_lock_fail();
    }

    *(uint64_t *)((char *)obj + offset) = value;
    n00b_field_lock_guard_unlock();
}

static void
n00b_builtin_field_set_and_lock(void *obj, int64_t offset, uint64_t value)
{
    n00b_field_lock_guard_write();

    if (n00b_field_lock_find(obj, offset)) {
        n00b_field_lock_guard_unlock();
        n00b_field_lock_fail();
    }

    *(uint64_t *)((char *)obj + offset) = value;
    n00b_field_lock_insert(obj, offset);
    n00b_field_lock_guard_unlock();
}

static n00b_cg_val_t
codegen_class_decl(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    // Find the class name. The @declares annotation already created
    // a sym entry. The class name is the identifier following "class".
    // Use n00b_pt_find_child_by_nt to find concrete-class or
    // parameterized-class, then extract the first token (the name).
    // Search children manually — n00b_pt_find_child_by_nt may have
    // string encoding issues with ncc-compiled code.
    n00b_parse_tree_t *class_node = NULL;
    size_t             nc         = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (n00b_pt_is_nt(child, "concrete-class")
            || n00b_pt_is_nt(child, "parameterized-class")) {
            class_node = child;
            break;
        }
    }

    if (!class_node) {
        return N00B_CG_VOID_VAL;
    }

    n00b_parse_tree_t *name_tok = n00b_pt_first_token(class_node);

    if (!name_tok) {
        return N00B_CG_VOID_VAL;
    }

    const char *class_name = n00b_pt_token_text(name_tok);
    size_t      class_len  = n00b_pt_token_text_len(name_tok);

    if (!class_name || class_len == 0) {
        return N00B_CG_VOID_VAL;
    }

    // Look up the class symbol to get its exposed_scope.
    n00b_annot_result_t *ar = current_annot(s);

    if (!ar || !ar->symtab) {
        return N00B_CG_VOID_VAL;
    }

    n00b_string_t    *name_str = n00b_string_from_raw(class_name, (int64_t)class_len);
    n00b_sym_entry_t *sym = n00b_symtab_lookup_any(ar->symtab, n00b_string_empty(), name_str);

    if (!sym || !sym->exposed_scope) {
        return N00B_CG_VOID_VAL;
    }

    // Compute the field layout.
    n00b_class_layout_t *layout = compute_class_layout(s, sym->exposed_scope);
    sym->class_layout           = layout;

    // Back-link from type to sym entry so field access can find the layout.
    // This is a fallback for cases where the type-based lookup doesn't work.
    if (sym->type_var) {
        n00b_tc_type_t *root = n00b_tc_find(sym->type_var);
        root->user_data      = sym;
    }

    return N00B_CG_VOID_VAL;
}

// ============================================================================
// Enum statement handler
// ============================================================================

static n00b_cg_val_t
codegen_enum_stmt(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    // Grammar: <enum-stmt> ::= <enum-prefix> IDENTIFIER? { <enum-items> }
    // Walk enum-items, assign auto-incrementing values (or explicit ones),
    // and store on the sym_entry's const_value.
    n00b_annot_result_t *ar = current_annot(s);

    if (!ar || !ar->symtab) {
        return N00B_CG_VOID_VAL;
    }

    // Find the enum-items child.
    n00b_parse_tree_t *items_node = NULL;
    size_t             nc         = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (child && n00b_pt_is_nt(child, "enum-items")) {
            items_node = child;
            break;
        }
    }

    if (!items_node) {
        return N00B_CG_VOID_VAL;
    }

    // DFS through enum-items to find all enum-item nodes.
    // Each enum-item has: IDENTIFIER [enum-value?]
    n00b_parse_tree_t *stack[128];
    int                sp       = 0;
    int64_t            next_val = 0;

    stack[sp++] = items_node;

    while (sp > 0) {
        n00b_parse_tree_t *cur = stack[--sp];

        if (!cur || n00b_pt_is_token(cur)) {
            continue;
        }

        if (n00b_pt_is_nt(cur, "enum-item")) {
            // Extract member name (first token).
            n00b_parse_tree_t *name_tok = n00b_pt_first_token(cur);

            if (!name_tok) {
                continue;
            }

            const char *name_raw = n00b_pt_token_text(name_tok);
            size_t      name_len = n00b_pt_token_text_len(name_tok);

            if (!name_raw || name_len == 0) {
                continue;
            }

            // Check for explicit value (enum-value child).
            int64_t val     = next_val;
            size_t  item_nc = n00b_pt_num_children(cur);

            for (size_t j = 0; j < item_nc; j++) {
                n00b_parse_tree_t *vc = n00b_pt_get_child(cur, j);

                if (vc && n00b_pt_is_nt(vc, "enum-value")) {
                    // enum-value has: ":" or "=" then a simple-lit.
                    n00b_parse_tree_t *lit_tok = NULL;
                    size_t             vnc     = n00b_pt_num_children(vc);

                    for (size_t k = 0; k < vnc; k++) {
                        n00b_parse_tree_t *vcc = n00b_pt_get_child(vc, k);

                        if (vcc && n00b_pt_is_token(vcc)) {
                            const char *t  = n00b_pt_token_text(vcc);
                            size_t      tl = n00b_pt_token_text_len(vcc);

                            // Skip ":" and "=" tokens.
                            if (tl == 1 && (t[0] == ':' || t[0] == '=')) {
                                continue;
                            }

                            lit_tok = vcc;
                            break;
                        }
                        else if (vcc && !n00b_pt_is_token(vcc)) {
                            // simple-lit wrapper — get its token.
                            lit_tok = n00b_pt_first_token(vcc);
                            break;
                        }
                    }

                    if (lit_tok) {
                        const char *vt  = n00b_pt_token_text(lit_tok);
                        size_t      vtl = n00b_pt_token_text_len(lit_tok);

                        if (vt && vtl > 0) {
                            char vbuf[vtl + 1];
                            memcpy(vbuf, vt, vtl);
                            vbuf[vtl] = '\0';
                            val       = strtoll(vbuf, NULL, 0);
                        }
                    }

                    break;
                }
            }

            // Find the symbol entry and set its const_value.
            n00b_string_t    *member_name = n00b_string_from_raw(name_raw, (int64_t)name_len);
            n00b_sym_entry_t *entry
                = n00b_symtab_lookup_any(ar->symtab, n00b_string_empty(), member_name);

            if (entry) {
                // Store the integer value as a heap-allocated int64_t.
                int64_t *heap_val  = n00b_alloc_array(int64_t, 1);
                *heap_val          = val;
                entry->const_value = n00b_option_set(void *, heap_val);
                entry->kind        = N00B_SYM_ENUM_CONST;
            }

            next_val = val + 1;
            continue; // Don't recurse into enum-item children.
        }

        // Push children in reverse for left-to-right traversal.
        size_t cnc = n00b_pt_num_children(cur);

        for (size_t i = cnc; i > 0; i--) {
            if (sp < 128) {
                stack[sp++] = n00b_pt_get_child(cur, i - 1);
            }
        }
    }

    return N00B_CG_VOID_VAL;
}

// ============================================================================
// Assert statement handler
// ============================================================================

// Runtime assert failure: called when assert expression is false.
static void
n00b_assert_fail_impl(int64_t line)
{
    if (line > 0) {
        fprintf(stderr, "n00b: assertion failed at line %lld\n", (long long)line);
    }
    else {
        fprintf(stderr, "n00b: assertion failed\n");
    }

    abort();
}

static n00b_cg_val_t
codegen_assert_stmt(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    // Grammar: <assert-stmt> ::= %"assert" <expression>
    // Evaluate the expression; if false, call abort helper with line number.
    size_t        nc   = n00b_pt_num_children(node);
    n00b_cg_val_t cond = N00B_CG_VOID_VAL;

    // Extract line number from the "assert" keyword token.
    int64_t            line      = 0;
    n00b_parse_tree_t *first_tok = n00b_pt_first_token(node);

    if (first_tok) {
        n00b_token_info_t *tok = n00b_parse_node_token(first_tok);

        if (tok) {
            line = (int64_t)tok->line;
        }
    }

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (!n00b_pt_is_token(child)) {
            cond = codegen_walk(s, child);
            break;
        }
    }

    if (cond.kind == N00B_CG_VAL_VOID) {
        return N00B_CG_VOID_VAL;
    }

    // bt cond, ok_label  (skip abort if condition is true)
    n00b_cg_val_t ok_label = n00b_cg_label_new(s);
    n00b_cg_emit_bt(s, cond, ok_label);

    // Call abort helper with line number.
    n00b_cg_type_tag_t pt[] = {N00B_CG_I64};
    n00b_cg_import_func(s,
                        "n00b_assert_fail",
                        (void *)n00b_assert_fail_impl,
                        .ret         = N00B_CG_VOID,
                        .param_types = pt,
                        .n_params    = 1);
    n00b_cg_val_t line_arg = _n00b_cg_const_i64(s, line);
    n00b_cg_emit_call(s, "n00b_assert_fail", &line_arg, 1, .ret = N00B_CG_VOID);

    n00b_cg_label_here(s, ok_label);

    return N00B_CG_VOID_VAL;
}

// ============================================================================
// Comptime block handler
// ============================================================================

// Process a comptime body statement: handles assignments and expression
// statements (method calls) using direct C execution.
static n00b_cg_val_t
comptime_walk_stmt(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    if (!node || n00b_pt_is_token(node)) {
        return N00B_CG_VOID_VAL;
    }

    n00b_nt_node_t *pn = &n00b_tree_node_value(node);

    // Skip group nodes.
    if (pn->group_top) {
        n00b_cg_val_t result = N00B_CG_VOID_VAL;
        size_t        nc     = n00b_pt_num_children(node);

        for (size_t i = 0; i < nc; i++) {
            n00b_cg_val_t v = comptime_walk_stmt(s, n00b_pt_get_child(node, i));

            if (v.kind != N00B_CG_VAL_VOID) {
                result = v;
            }
        }

        return result;
    }

    // Check if this is an assign-stmt (CF_ASSIGNS annotation).
    n00b_cf_label_t *cf = n00b_codegen_cf_label(s, node);

    if (cf && cf->kind == N00B_CF_ASSIGNS) {
        // Evaluate the RHS.
        n00b_cg_val_t value = N00B_CG_VOID_VAL;

        if (cf->then_body) {
            value = comptime_walk_stmt(s, cf->then_body);
        }

        // Store in comptime_vars.
        if (cf->cond && value.kind != N00B_CG_VAL_VOID) {
            n00b_parse_tree_t *name_tok = n00b_pt_first_token(cf->cond);

            if (name_tok) {
                const char *raw  = n00b_pt_token_text(name_tok);
                size_t      rlen = n00b_pt_token_text_len(name_tok);

                if (raw && rlen > 0) {
                    char *name = n00b_alloc_array(char, rlen + 1);
                    memcpy(name, raw, rlen);
                    name[rlen] = '\0';

                    if (!s->comptime_vars) {
                        s->comptime_vars = n00b_alloc(n00b_dict_untyped_t);
                        n00b_dict_untyped_init(s->comptime_vars, .hash = n00b_hash_cstring);
                    }

                    // Store the pointer from the IMM value.
                    void *obj = (void *)(uintptr_t)value.aux;
                    n00b_dict_untyped_put(s->comptime_vars, (void *)name, obj);
                }
            }
        }

        return value;
    }

    // Check if this is a call (method call on a comptime var).
    if (cf && cf->kind == N00B_CF_CALL) {
        // Check for method call pattern: postfix-expr with "." child.
        if (cf->cond) {
            // Look for a "." token child in the callee node to detect
            // obj.method() pattern.
            size_t nc      = n00b_pt_num_children(cf->cond);
            bool   has_dot = false;

            for (size_t i = 0; i < nc; i++) {
                n00b_parse_tree_t *ch = n00b_pt_get_child(cf->cond, i);

                if (n00b_pt_is_token(ch)) {
                    const char *tt = n00b_pt_token_text(ch);
                    size_t      tl = n00b_pt_token_text_len(ch);

                    if (tl == 1 && tt[0] == '.') {
                        has_dot = true;
                        break;
                    }
                }
            }

            if (has_dot) {
                // Extract object name (first token) and method name (last token).
                const char *obj_name     = NULL;
                size_t      obj_name_len = 0;
                const char *method_name  = NULL;
                size_t      method_len   = 0;

                for (size_t i = 0; i < nc; i++) {
                    n00b_parse_tree_t *ch = n00b_pt_get_child(cf->cond, i);

                    if (n00b_pt_is_token(ch)) {
                        const char *tt = n00b_pt_token_text(ch);
                        size_t      tl = n00b_pt_token_text_len(ch);

                        if (!tt || tl == 0) {
                            continue;
                        }

                        if (tl == 1 && tt[0] == '.') {
                            continue;
                        }

                        if (!obj_name) {
                            obj_name     = tt;
                            obj_name_len = tl;
                        }
                        else {
                            method_name = tt;
                            method_len  = tl;
                        }
                    }
                    else {
                        // Non-token child: recurse to find tokens.
                        n00b_parse_tree_t *ft = n00b_pt_first_token(ch);

                        if (ft) {
                            const char *tt = n00b_pt_token_text(ft);
                            size_t      tl = n00b_pt_token_text_len(ft);

                            if (tt && tl > 0) {
                                if (!obj_name) {
                                    obj_name     = tt;
                                    obj_name_len = tl;
                                }
                                else {
                                    method_name = tt;
                                    method_len  = tl;
                                }
                            }
                        }
                    }
                }

                if (obj_name && method_name && s->comptime_vars) {
                    // Look up the object.
                    char   nbuf[128];
                    size_t copy = obj_name_len < 127 ? obj_name_len : 127;
                    memcpy(nbuf, obj_name, copy);
                    nbuf[copy] = '\0';

                    bool  found = false;
                    void *obj   = n00b_dict_untyped_get(s->comptime_vars, (void *)nbuf, &found);

                    if (found && obj) {
                        // Look up the method.
                        char   mbuf[128];
                        size_t mcopy = method_len < 127 ? method_len : 127;
                        memcpy(mbuf, method_name, mcopy);
                        mbuf[mcopy] = '\0';

                        uint64_t thash  = n00b_obj_typehash(obj);
                        auto     fn_opt = n00b_type_method_lookup(thash, mbuf);

                        if (n00b_option_is_set(fn_opt)) {
                            // Call the method directly in C.
                            void (*fn)(void *) = (void (*)(void *))n00b_option_get(fn_opt);
                            fn(obj);
                        }
                        else {
                            codegen_error(
                                s,
                                cf->self,
                                "CG003",
                                n00b_unicode_str_to_cstr(n00b_cformat(
                                    "comptime: no method '[|#|]' on object '[|#|]'",
                                    n00b_string_from_cstr(mbuf),
                                    n00b_string_from_cstr(nbuf))));
                        }
                    }
                    else {
                        codegen_error(
                            s,
                            cf->self,
                            "CG004",
                            n00b_unicode_str_to_cstr(n00b_cformat(
                                "comptime: variable '[|#|]' not found",
                                n00b_string_from_cstr(nbuf))));
                    }
                }

                return N00B_CG_VOID_VAL;
            }
        }
    }

    // Check for embed literal (simple-lit with modifier).
    if (n00b_pt_is_nt(node, "simple-lit")) {
        n00b_parse_tree_t *first = n00b_pt_first_token(node);

        if (first) {
            n00b_token_info_t *tok = n00b_parse_node_token(first);

            if (codegen_token_is_terminal(s, tok, "EMBED")) {
                return codegen_embed(s, node);
            }
        }
    }

    // Default: recurse into children.
    n00b_cg_val_t result = N00B_CG_VOID_VAL;
    size_t        nc2    = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc2; i++) {
        n00b_cg_val_t v = comptime_walk_stmt(s, n00b_pt_get_child(node, i));

        if (v.kind != N00B_CG_VAL_VOID) {
            result = v;
        }
    }

    return result;
}

// Process a comptime block: walk body children with direct C execution.
static void
comptime_process_body(n00b_cg_session_t *s, n00b_parse_tree_t *body)
{
    if (!body) {
        return;
    }

    bool was_comptime = s->in_comptime;
    s->in_comptime    = true;

    size_t nc = n00b_pt_num_children(body);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(body, i);
        comptime_walk_stmt(s, child);
    }

    s->in_comptime = was_comptime;
}

static n00b_cg_val_t
codegen_comptime(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    n00b_cg_module_t *m = s->active_module;

    // In pass 2 (cur_func is set), comptime was already processed in
    // pass 1 — skip it.
    if (m && m->cur_func) {
        return N00B_CG_VOID_VAL;
    }

    // Pass 1 context: process the comptime body directly.
    // Find the <body> child (skip the "comptime" keyword token).
    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (!n00b_pt_is_token(child)) {
            comptime_process_body(s, child);
            break;
        }
    }

    return N00B_CG_VOID_VAL;
}

// ============================================================================
// Function definition handler
// ============================================================================

static n00b_cg_val_t
codegen_func_def(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    // Grammar:
    // <func-def> @scope("function", $3) @declares($3, "function") ::=
    //     <func-mod>* <func-kind> IDENTIFIER <param-decl>
    //     <where-clause>? <return-type>? <body>
    //
    // Walk children to extract: name, params, return type, body.
    // Return type is a trailing `-> type` after params/where-clause.
    const char        *func_name     = NULL;
    n00b_parse_tree_t *param_decl    = NULL;
    n00b_parse_tree_t *body_node     = NULL;
    n00b_parse_tree_t *ret_type_node = NULL;
    bool               saw_method_kw = false;

    size_t nc          = n00b_pt_num_children(node);
    bool   saw_func_kw = false;

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (n00b_pt_is_token(child)) {
            const char *tt = n00b_pt_token_text(child);
            size_t      tl = n00b_pt_token_text_len(child);

            if (!tt || tl == 0) {
                continue;
            }

            // Check for "func" or "method" keyword.
            if (tl == 4 && memcmp(tt, "func", 4) == 0) {
                saw_func_kw = true;
                continue;
            }

            if (tl == 6 && memcmp(tt, "method", 6) == 0) {
                saw_func_kw   = true;
                saw_method_kw = true;
                continue;
            }

            // Skip "->" token (part of return-type, handled as NT).
            if (tl == 2 && memcmp(tt, "->", 2) == 0) {
                continue;
            }

            // The IDENTIFIER after func/method is the function name.
            if (saw_func_kw && !func_name) {
                char *buf = n00b_alloc_array(char, tl + 1);
                memcpy(buf, tt, tl);
                buf[tl]   = '\0';
                func_name = buf;
                continue;
            }
        }
        else if (n00b_pt_is_group(child)) {
            if (saw_func_kw && param_decl) {
                n00b_parse_tree_t *maybe_ret = codegen_find_nt_deep(child, "return-type");

                if (maybe_ret) {
                    ret_type_node = maybe_ret;
                }
            }

            continue;
        }
        else {
            // Non-terminal children: func-mod, func-kind, param-decl,
            // where-clause, return-type, or body.

            // Before the func keyword: func-mod or func-kind.
            if (!saw_func_kw) {
                // <func-kind> is "func" | "method" — check first token.
                n00b_parse_tree_t *ft = n00b_pt_first_token(child);

                if (ft) {
                    const char *ftt = n00b_pt_token_text(ft);
                    size_t      ftl = n00b_pt_token_text_len(ft);

                    if (ftt && ftl == 4 && memcmp(ftt, "func", 4) == 0) {
                        saw_func_kw = true;
                        continue;
                    }

                    if (ftt && ftl == 6 && memcmp(ftt, "method", 6) == 0) {
                        saw_func_kw   = true;
                        saw_method_kw = true;
                        continue;
                    }
                }
                // func-mod (private, once) — skip.
                continue;
            }

            if (!func_name) {
                // Check for <method-name> NT: ClassName.methodName
                if (n00b_pt_is_nt(child, "method-name")) {
                    // Extract class name and method name from the NT.
                    const char *mn_class      = NULL;
                    size_t      mn_class_len  = 0;
                    const char *mn_method     = NULL;
                    size_t      mn_method_len = 0;

                    size_t mnc = n00b_pt_num_children(child);

                    for (size_t mi = 0; mi < mnc; mi++) {
                        n00b_parse_tree_t *mc = n00b_pt_get_child(child, mi);

                        if (!n00b_pt_is_token(mc)) {
                            continue;
                        }

                        const char *mt  = n00b_pt_token_text(mc);
                        size_t      mtl = n00b_pt_token_text_len(mc);

                        if (mtl == 1 && mt[0] == '.') {
                            continue;
                        }

                        if (!mn_class) {
                            mn_class     = mt;
                            mn_class_len = mtl;
                        }
                        else if (!mn_method) {
                            mn_method     = mt;
                            mn_method_len = mtl;
                        }
                    }

                    if (mn_class && mn_method) {
                        // Build mangled name: ClassName$methodName
                        size_t mlen = mn_class_len + 1 + mn_method_len;
                        char  *mbuf = n00b_alloc_array(char, mlen + 1);
                        memcpy(mbuf, mn_class, mn_class_len);
                        mbuf[mn_class_len] = '$';
                        memcpy(mbuf + mn_class_len + 1, mn_method, mn_method_len);
                        mbuf[mlen] = '\0';
                        func_name  = mbuf;
                    }
                }

                continue;
            }

            // After the name: param-decl, where-clause, return-type, body.
            // param-decl is first, body is always last.
            // Collect all NT children after name; last one is body,
            // and if there's a return-type (contains "->") we capture it.
            if (!param_decl) {
                param_decl = child;
            }
            else {
                // Check if this NT is a return-type by looking for "->".
                n00b_parse_tree_t *ft     = n00b_pt_first_token(child);
                bool               is_ret = false;

                if (ft) {
                    const char *ftt = n00b_pt_token_text(ft);
                    size_t      ftl = n00b_pt_token_text_len(ft);

                    if (ftt && ftl == 2 && memcmp(ftt, "->", 2) == 0) {
                        is_ret = true;
                    }
                }

                if (is_ret) {
                    ret_type_node = child;
                }
                else {
                    // where-clause or body — body is always last.
                    body_node = child;
                }
            }
        }
    }

    if (!func_name) {
        return codegen_children_default(s, node);
    }

    bool is_private_func = codegen_func_decl_has_modifier(node, "private");
    bool is_once_func    = codegen_func_decl_has_modifier(node, "once");

    // Determine return type.
    n00b_cg_type_tag_t ret_type = N00B_CG_I64;

    if (ret_type_node) {
        n00b_parse_tree_t *type_node = codegen_find_nt_deep(ret_type_node, "union-tspec");
        if (!type_node) {
            type_node = codegen_find_nt_deep(ret_type_node, "type-spec");
        }

        ret_type = type_node ? codegen_decl_type_tag(s, type_node)
                             : n00b_codegen_node_type(s, ret_type_node);
    }
    else {
        // Try to get from the func-def node's own type.
        ret_type = n00b_codegen_node_type(s, node);
    }

    // Function definitions must be emitted as top-level MIR functions.
    // If we're inside a wrapper function (like _eval in the REPL),
    // we can't nest MIR functions. Instead, we use the deferred
    // approach: the func-def is emitted *outside* the wrapper by
    // n00b_cg_emit_func_from_tree's pre-scan pass. When we reach
    // here during normal tree-walk, the function was already emitted,
    // so we just return void.
    //
    // If we're NOT inside a wrapper (cur_func == NULL), emit directly.
    n00b_cg_module_t *m = s->active_module;

    if (m->cur_func != NULL) {
        // Inside a wrapper — func was already emitted in the pre-scan.
        return N00B_CG_VOID_VAL;
    }

    // For bare method declarations (method keyword, no dotted name),
    // look up the mangled name from the annotation walk's symtab.
    if (saw_method_kw && func_name && !strchr(func_name, '$')) {
        n00b_annot_result_t *ar = current_annot(s);

        if (ar && ar->symtab) {
            // The annotation walk created a mangled entry ClassName$methodName.
            // Look it up by scanning all scopes for a matching method sym.
            size_t            fn_len = strlen(func_name);
            n00b_namespace_t *ns     = &ar->symtab->namespaces[0]; // default ns

            n00b_sym_entry_t *e;
            for (int32_t si = 0; si < ns->all_count; si++) {
                n00b_scope_t *sc = ns->all_scopes[si];

                for (e = sc->first_in_scope; e; e = e->next_in_scope) {
                    if (e->kind == N00B_SYM_FUNCTION && e->is_method && e->name
                        && e->name->u8_bytes > fn_len + 1) {
                        const char *d = memchr(e->name->data, '$', e->name->u8_bytes);

                        if (d && (size_t)(e->name->u8_bytes - (d - e->name->data) - 1) == fn_len
                            && memcmp(d + 1, func_name, fn_len) == 0) {
                            char *mbuf = n00b_alloc_array(char, e->name->u8_bytes + 1);
                            memcpy(mbuf, e->name->data, e->name->u8_bytes);
                            mbuf[e->name->u8_bytes] = '\0';
                            func_name               = mbuf;
                            goto found_mangled;
                        }
                    }
                }
            }
found_mangled:;
        }
    }

    // Check if this is a method (mangled name contains '$').
    bool is_method_def = false;

    const char *p;
    for (p = func_name; *p; p++) {
        if (*p == '$') {
            is_method_def = true;
            break;
        }
    }

    codegen_func_meta_t *meta = codegen_func_meta_new(s,
                                                      func_name,
                                                      param_decl,
                                                      ret_type,
                                                      is_private_func,
                                                      is_once_func);
    codegen_store_func_meta(s, meta);

    if (is_private_func) {
        n00b_cg_module_mark_private_func(s->active_module, func_name);
    }

    const char        *param_names[32];
    n00b_cg_type_tag_t param_types[32];
    int32_t            n_params = 0;

    if (is_method_def && n_params < 32) {
        param_names[n_params] = "self";
        param_types[n_params] = N00B_CG_I64;
        n_params++;
    }

    for (int32_t i = 0; i < meta->n_params && n_params < 32; i++) {
        param_names[n_params] = meta->params[i].name;
        param_types[n_params] = meta->params[i].type;
        n_params++;
    }

    // Top-level emit: not inside any function.
    n00b_cg_begin_func(s,
                       func_name,
                       .ret         = ret_type,
                       .param_names = (const char **)param_names,
                       .param_types = param_types,
                       .n_params    = n_params);

    for (int32_t i = 0; i < n_params; i++) {
        codegen_store_local_type(s, param_names[i], param_types[i]);
    }

    // Stamp each parameter's MIR register with its registered-type
    // typehash so postfix-`.` extension-method dispatch (codegen.c
    // fallback + `n00b_codegen_method_dispatch`) can find the method
    // on the receiver's type at runtime. The implicit `self` parameter
    // for method declarations does not flow through `meta->params`
    // (it lives at param index 0 when `is_method_def` is true); we
    // skip it here since class instances are dispatched through their
    // existing class-layout machinery.
    {
        int32_t self_offset = is_method_def ? 1 : 0;

        for (int32_t i = 0; i < meta->n_params; i++) {
            if (meta->params[i].type_hash) {
                n00b_cg_val_t pv = n00b_cg_param(s, i + self_offset);
                n00b_cg_val_set_type_hash(s, pv, meta->params[i].type_hash);
            }
        }
    }

    uint64_t           saved_once_key = s->current_once_key;
    n00b_cg_type_tag_t saved_ret_type = s->current_func_ret_type;
    s->current_func_ret_type          = ret_type;

    if (is_once_func) {
        s->current_once_key = codegen_once_key_value(s, func_name);
        codegen_import_once_helpers(s);

        n00b_cg_val_t key = codegen_once_key(s);
        n00b_cg_val_t done
            = n00b_cg_emit_call(s, "n00b_builtin_once_is_done", &key, 1, .ret = N00B_CG_I64);
        n00b_cg_val_t body_label = n00b_cg_label_new(s);
        n00b_cg_emit_bf(s, done, body_label);

        if (ret_type == N00B_CG_VOID) {
            n00b_cg_emit_ret_void(s);
        }
        else {
            const char   *get_helper = codegen_once_get_helper(ret_type);
            n00b_cg_val_t cached = n00b_cg_emit_call(s, get_helper, &key, 1, .ret = ret_type);
            n00b_cg_emit_ret(s, cached);
        }

        n00b_cg_label_here(s, body_label);
    }

    n00b_cg_val_t body_result = N00B_CG_VOID_VAL;

    if (body_node) {
        bool body_has_yield = codegen_tree_contains_statement_yield(body_node);

        if (body_has_yield) {
            bool body_yielded = false;
            bool saved_reject = s->reject_unconsumed_yield;

            s->reject_unconsumed_yield = ret_type == N00B_CG_VOID;
            body_result                = codegen_block_value(s, body_node, &body_yielded);
            s->reject_unconsumed_yield = saved_reject;

            if (ret_type != N00B_CG_VOID && !body_yielded && !s->has_codegen_errors) {
                codegen_error(s,
                              body_node,
                              "CG022",
                              "value-producing function does not yield on every path");
            }
        }
        else {
            body_result = codegen_walk(s, body_node);
        }
    }

    if (body_result.kind != N00B_CG_VAL_VOID) {
        codegen_once_store_return(s, body_result);
        n00b_cg_emit_ret(s, body_result);
    }
    else if (ret_type == N00B_CG_VOID) {
        codegen_once_store_return(s, N00B_CG_VOID_VAL);
        n00b_cg_emit_ret_void(s);
    }
    else {
        n00b_cg_val_t zero = codegen_zero_for_type(s, ret_type);
        codegen_once_store_return(s, zero);
        n00b_cg_emit_ret(s, zero);
    }

    s->current_once_key      = saved_once_key;
    s->current_func_ret_type = saved_ret_type;

    n00b_cg_end_func(s);

    return N00B_CG_VOID_VAL;
}

// ============================================================================
// Default: lower all children
// ============================================================================

static bool
postfix_token_is_slice_sep(n00b_parse_tree_t *node)
{
    if (!node || !n00b_pt_is_token(node)) {
        return false;
    }

    const char *txt = n00b_pt_token_text(node);
    size_t      len = n00b_pt_token_text_len(node);

    return txt && len == 1 && txt[0] == ':';
}

static bool
postfix_index_contents_info(n00b_parse_tree_t *index_node, codegen_index_info_t *info)
{
    if (!index_node || !n00b_pt_is_nt(index_node, "index-contents") || !info) {
        return false;
    }

    bool   saw_sep = false;
    size_t nc      = n00b_pt_num_children(index_node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(index_node, i);

        if (!child) {
            continue;
        }

        if (n00b_pt_is_nt(child, "range-sep") || postfix_token_is_slice_sep(child)) {
            info->is_slice = true;
            saw_sep        = true;
            continue;
        }

        if (n00b_pt_is_nt(child, "expression")) {
            if (!saw_sep && !info->has_start) {
                info->start     = child;
                info->has_start = true;
            }
            else if (!info->has_end) {
                info->end     = child;
                info->has_end = true;
            }
            else {
                return false;
            }
        }
    }

    return info->is_slice || info->has_start;
}

static bool
postfix_index_info(n00b_parse_tree_t *node, codegen_index_info_t *info)
{
    if (!node || !info || !n00b_pt_is_nt(node, "postfix-expr")) {
        return false;
    }

    *info = (codegen_index_info_t){0};

    bool               saw_open   = false;
    n00b_parse_tree_t *container  = NULL;
    n00b_parse_tree_t *index_node = NULL;
    size_t             nc         = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (!child) {
            continue;
        }

        if (n00b_pt_is_token(child)) {
            const char *txt = n00b_pt_token_text(child);
            size_t      len = n00b_pt_token_text_len(child);

            if (len == 1 && txt[0] == '[') {
                saw_open = true;
            }

            continue;
        }

        if (!saw_open) {
            container = child;
        }
        else if (n00b_pt_is_nt(child, "index-contents")) {
            index_node = child;
        }
    }

    if (!saw_open || !container) {
        return false;
    }

    info->container = container;
    return postfix_index_contents_info(index_node, info);
}

static bool
postfix_index_parts(n00b_parse_tree_t  *node,
                    n00b_parse_tree_t **container_out,
                    n00b_parse_tree_t **index_expr_out)
{
    codegen_index_info_t info = {0};

    if (!postfix_index_info(node, &info) || info.is_slice || !info.start) {
        return false;
    }

    *container_out  = info.container;
    *index_expr_out = info.start;
    return true;
}

static bool
postfix_has_index_brackets(n00b_parse_tree_t *node)
{
    if (!node || !n00b_pt_is_nt(node, "postfix-expr")) {
        return false;
    }

    size_t nc = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

        if (!child || !n00b_pt_is_token(child)) {
            continue;
        }

        const char *txt = n00b_pt_token_text(child);
        size_t      len = n00b_pt_token_text_len(child);

        if (len == 1 && txt[0] == '[') {
            return true;
        }
    }

    return false;
}

static n00b_cg_val_t
codegen_postfix_index(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    codegen_index_info_t info = {0};

    if (!postfix_index_info(node, &info)) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_val_t container = codegen_walk(s, info.container);

    if (container.kind == N00B_CG_VAL_VOID) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_type_tag_t container_type = container.type_tag;

    if (container_type != N00B_CG_LIST && container_type != N00B_CG_DICT
        && container_type != N00B_CG_STRING && container_type != N00B_CG_SET) {
        n00b_cg_type_tag_t inferred = n00b_codegen_node_type(s, info.container);

        if (inferred == N00B_CG_LIST || inferred == N00B_CG_DICT || inferred == N00B_CG_STRING
            || inferred == N00B_CG_SET) {
            container.type_tag = inferred;
            container_type     = inferred;
        }
    }

    if (container_type == N00B_CG_SET) {
        codegen_error(s, node, "CG010", "set values are not indexable");
        return N00B_CG_VOID_VAL;
    }

    if (container_type != N00B_CG_LIST && container_type != N00B_CG_DICT
        && container_type != N00B_CG_STRING) {
        return N00B_CG_VOID_VAL;
    }

    if (info.is_slice) {
        if (container_type == N00B_CG_DICT) {
            codegen_error(s,
                          node,
                          "CG010",
                          "dictionary slices are not supported; use a single key");
            return N00B_CG_VOID_VAL;
        }

        n00b_cg_val_t start = codegen_index_bound_or_default(s, info.start, 0);
        n00b_cg_val_t end   = codegen_index_bound_or_default(s, info.end, 0);

        if (start.kind == N00B_CG_VAL_VOID || end.kind == N00B_CG_VAL_VOID) {
            return N00B_CG_VOID_VAL;
        }

        n00b_cg_val_t has_start = _n00b_cg_const_i64(s, info.has_start ? 1 : 0);
        n00b_cg_val_t has_end   = _n00b_cg_const_i64(s, info.has_end ? 1 : 0);
        n00b_cg_val_t args[]    = {container, start, has_start, end, has_end};

        if (container_type == N00B_CG_LIST) {
            n00b_cg_type_tag_t slice_pt[]
                = {N00B_CG_LIST, N00B_CG_I64, N00B_CG_I64, N00B_CG_I64, N00B_CG_I64};

            n00b_cg_import_func(s,
                                "n00b_builtin_list_slice",
                                (void *)n00b_builtin_list_slice,
                                .ret         = N00B_CG_I64,
                                .param_types = slice_pt,
                                .n_params    = 5);

            n00b_cg_val_t result
                = n00b_cg_emit_call(s, "n00b_builtin_list_slice", args, 5, .ret = N00B_CG_I64);
            result.type_tag = N00B_CG_LIST;
            return result;
        }

        n00b_cg_type_tag_t slice_pt[]
            = {N00B_CG_STRING, N00B_CG_I64, N00B_CG_I64, N00B_CG_I64, N00B_CG_I64};

        n00b_cg_import_func(s,
                            "n00b_builtin_str_slice",
                            (void *)n00b_builtin_str_slice,
                            .ret         = N00B_CG_I64,
                            .param_types = slice_pt,
                            .n_params    = 5);

        n00b_cg_val_t result
            = n00b_cg_emit_call(s, "n00b_builtin_str_slice", args, 5, .ret = N00B_CG_I64);
        result.type_tag = N00B_CG_STRING;
        return result;
    }

    n00b_cg_val_t index = codegen_walk(s, info.start);

    if (index.kind == N00B_CG_VAL_VOID) {
        return N00B_CG_VOID_VAL;
    }

    n00b_cg_val_t result = N00B_CG_VOID_VAL;

    if (container_type == N00B_CG_LIST) {
        n00b_cg_type_tag_t get_pt[] = {N00B_CG_LIST, N00B_CG_I64};

        n00b_cg_import_func(s,
                            "n00b_builtin_list_get_i64",
                            (void *)n00b_builtin_list_get_i64,
                            .ret         = N00B_CG_I64,
                            .param_types = get_pt,
                            .n_params    = 2);

        n00b_cg_val_t args[] = {container, index};
        result = n00b_cg_emit_call(s, "n00b_builtin_list_get_i64", args, 2, .ret = N00B_CG_I64);
    }
    else if (container_type == N00B_CG_DICT) {
        n00b_cg_type_tag_t get_pt[] = {N00B_CG_DICT, N00B_CG_I64, N00B_CG_I64};

        n00b_cg_import_func(s,
                            "n00b_builtin_dict_get_value_payload",
                            (void *)n00b_builtin_dict_get_value_payload,
                            .ret         = N00B_CG_I64,
                            .param_types = get_pt,
                            .n_params    = 3);

        n00b_cg_val_t index_tag = _n00b_cg_const_i64(s, (int64_t)index.type_tag);
        n00b_cg_val_t args[]    = {container, index, index_tag};
        result                  = n00b_cg_emit_call(s,
                                   "n00b_builtin_dict_get_value_payload",
                                   args,
                                   3,
                                   .ret = N00B_CG_I64);
    }
    else {
        n00b_cg_type_tag_t get_pt[] = {N00B_CG_STRING, N00B_CG_I64};

        n00b_cg_import_func(s,
                            "n00b_builtin_str_get",
                            (void *)n00b_builtin_str_get,
                            .ret         = N00B_CG_I64,
                            .param_types = get_pt,
                            .n_params    = 2);

        n00b_cg_val_t args[] = {container, index};
        result = n00b_cg_emit_call(s, "n00b_builtin_str_get", args, 2, .ret = N00B_CG_I64);
        result.type_tag = N00B_CG_STRING;
        return result;
    }

    result.type_tag = n00b_codegen_node_type(s, node);
    return result;
}

static n00b_cg_val_t
codegen_children_default(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    n00b_cg_val_t result = N00B_CG_VOID_VAL;
    size_t        nc     = n00b_pt_num_children(node);

    for (size_t i = 0; i < nc; i++) {
        if (s->has_codegen_errors) {
            break;
        }

        n00b_parse_tree_t *child = n00b_pt_get_child(node, i);
        n00b_cg_val_t      val   = codegen_walk(s, child);

        if (val.kind != N00B_CG_VAL_VOID) {
            result = val;
        }
    }

    return result;
}

static n00b_cg_val_t
codegen_expression_stmt(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    bool saved_reject = s->reject_unconsumed_yield;

    if (!saved_reject) {
        return codegen_children_default(s, node);
    }

    s->reject_unconsumed_yield = true;
    n00b_cg_val_t result       = codegen_children_default(s, node);
    s->reject_unconsumed_yield = saved_reject;

    if (!s->has_codegen_errors && result.kind != N00B_CG_VAL_VOID
        && codegen_expression_stmt_has_direct_yield_value(node)) {
        codegen_error(s, node, "CG022", "yield value is not consumed in this context");
        return N00B_CG_VOID_VAL;
    }

    return result;
}

// ============================================================================
// Core tree walk
// ============================================================================

static bool
annot_is_semantic(n00b_annot_kind_t kind)
{
    switch (kind) {
    case N00B_ANNOT_OPERATOR:
    case N00B_ANNOT_LITERAL:
    case N00B_ANNOT_CALL:
    case N00B_ANNOT_ASSIGNS:
    case N00B_ANNOT_VARREF:
    case N00B_ANNOT_BRANCH:
    case N00B_ANNOT_LOOP:
    case N00B_ANNOT_SWITCH:
    case N00B_ANNOT_JUMP:
    case N00B_ANNOT_CAPTURE:
        return true;
    default:
        return false;
    }
}

static bool
annot_is_format_only(n00b_annot_kind_t kind)
{
    switch (kind) {
    case N00B_ANNOT_INDENT:
    case N00B_ANNOT_NEWLINE:
    case N00B_ANNOT_SPACE:
    case N00B_ANNOT_NOSPACE:
    case N00B_ANNOT_GROUP:
    case N00B_ANNOT_SOFTLINE:
    case N00B_ANNOT_HARDLINE:
    case N00B_ANNOT_ALIGN:
    case N00B_ANNOT_CONCAT:
    case N00B_ANNOT_BLANKLINE:
    case N00B_ANNOT_PENALTY:
    case N00B_ANNOT_NOTRIVIA:
        return true;
    default:
        return false;
    }
}

static n00b_cg_val_t
codegen_walk(n00b_cg_session_t *s, n00b_parse_tree_t *node)
{
    if (!node) {
        return N00B_CG_VOID_VAL;
    }

    if (s->has_codegen_errors) {
        return N00B_CG_VOID_VAL;
    }

    // Leaf token: return VOID.
    // Literal tokens are handled by @literal annotations on their parent
    // node (codegen_literal), and operator tokens are extracted by
    // codegen_operator. Bare tokens (keywords, punctuation, newlines)
    // should not produce values.
    if (n00b_parse_node_is_token(node)) {
        return N00B_CG_VOID_VAL;
    }

    n00b_nt_node_t *pn = &n00b_tree_node_value(node);

    // Skip group nodes: recurse through them.
    if (pn->group_top) {
        return codegen_children_default(s, node);
    }

    // Check for explicit handler.
    if (s->handlers && pn->id >= 0 && pn->id < s->handler_cap && s->handlers[pn->id]) {
        return s->handlers[pn->id](s, node);
    }

    // Check CF labels.
    n00b_cf_label_t *cf = n00b_codegen_cf_label(s, node);

    if (cf) {
        switch (cf->kind) {
        case N00B_CF_BRANCH:
            return codegen_branch(s, cf);
        case N00B_CF_LOOP:
            return codegen_loop(s, cf);
        case N00B_CF_JUMP:
            return codegen_jump(s, cf);
        case N00B_CF_ASSIGNS:
            return codegen_assign(s, cf);
        case N00B_CF_VARREF:
            return codegen_varref(s, cf);
        case N00B_CF_SWITCH:
            return codegen_switch(s, cf);
        case N00B_CF_UNWRAP_RESULT:
            return codegen_unwrap_result(s, cf);
        case N00B_CF_CALL:
            return codegen_call_cf(s, cf);
        case N00B_CF_CAPTURE:
            break;
        }
    }

    // Member access: expr.name
    // Handles: enum constants (Color.Red), class field access (p.x).
    if (n00b_pt_is_nt(node, "postfix-expr")) {
        n00b_cg_val_t indexed = codegen_postfix_index(s, node);

        if (s->has_codegen_errors) {
            return N00B_CG_VOID_VAL;
        }

        if (indexed.kind != N00B_CG_VAL_VOID) {
            return indexed;
        }

        if (postfix_has_index_brackets(node)) {
            codegen_error(
                s,
                node,
                "CG010",
                "slice syntax and this indexed access are not supported by the MIR JIT yet");
            return N00B_CG_VOID_VAL;
        }

        size_t             mnc      = n00b_pt_num_children(node);
        bool               has_dot  = false;
        n00b_parse_tree_t *lhs_node = NULL;
        const char        *rhs_name = NULL;
        size_t             rhs_len  = 0;

        for (size_t i = 0; i < mnc; i++) {
            n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

            if (n00b_pt_is_token(child)) {
                const char *t  = n00b_pt_token_text(child);
                size_t      tl = n00b_pt_token_text_len(child);

                if (tl == 1 && t[0] == '.') {
                    has_dot = true;
                }
                else if (has_dot && tl > 0) {
                    rhs_name = t;
                    rhs_len  = tl;
                }
            }
            else if (!has_dot) {
                lhs_node = child;
            }
        }

        if (has_dot && lhs_node && rhs_name && rhs_len > 0) {
            n00b_annot_result_t *ar = current_annot(s);

            if (ar && ar->symtab) {
                // First try: LHS is a type/enum name with exposed_scope
                // (e.g., Color.Red).
                n00b_parse_tree_t *lhs_tok = n00b_pt_first_token(lhs_node);

                if (lhs_tok) {
                    const char *lhs_name = n00b_pt_token_text(lhs_tok);
                    size_t      lhs_len  = n00b_pt_token_text_len(lhs_tok);

                    if (lhs_name && lhs_len > 0) {
                        n00b_string_t *lhs_str
                            = n00b_string_from_raw(lhs_name, (int64_t)lhs_len);
                        n00b_sym_entry_t *sym
                            = n00b_symtab_lookup_any(ar->symtab, n00b_string_empty(), lhs_str);

                        if (sym && sym->exposed_scope) {
                            n00b_string_t *rhs_str
                                = n00b_string_from_raw(rhs_name, (int64_t)rhs_len);
                            n00b_sym_entry_t *member = NULL;

                            n00b_sym_entry_t *e;
                            for (e = sym->exposed_scope->first_in_scope; e;
                                 e = e->next_in_scope) {
                                if (e->name && e->name->u8_bytes == rhs_str->u8_bytes
                                    && memcmp(e->name->data, rhs_str->data, rhs_str->u8_bytes)
                                           == 0) {
                                    member = e;
                                    break;
                                }
                            }

                            // Enum constant access.
                            if (member && n00b_option_is_set(member->const_value)) {
                                int64_t *valp = n00b_option_get(member->const_value);
                                return _n00b_cg_const_i64(s, *valp);
                            }
                        }
                    }
                }

                // Second try: LHS is an instance variable, RHS is a field.
                // Resolve LHS type via the type system, find the class
                // sym entry by type name, and get the field layout.
                n00b_cg_val_t obj_val = codegen_walk(s, lhs_node);

                if (obj_val.kind != N00B_CG_VAL_VOID) {
                    // Get the LHS type from the annotation result.
                    n00b_tc_type_t      *lhs_type = n00b_codegen_node_tc_type(s, lhs_node);
                    n00b_class_layout_t *layout   = NULL;
                    n00b_sym_entry_t    *type_sym = NULL;

                    if (lhs_type) {
                        // If the type is a named Prim (class name),
                        // look up the class sym entry by name.
                        if (n00b_variant_is_type(lhs_type->kind, n00b_tc_prim_t)) {
                            n00b_tc_prim_t prim
                                = n00b_variant_get(lhs_type->kind, n00b_tc_prim_t);

                            if (prim.name && prim.name->u8_bytes > 0) {
                                type_sym = n00b_symtab_lookup_any(ar->symtab,
                                                                  n00b_string_empty(),
                                                                  prim.name);
                            }
                        }
                        else if (n00b_variant_is_type(lhs_type->kind, n00b_tc_record_t)) {
                            n00b_tc_record_t rec
                                = n00b_variant_get(lhs_type->kind, n00b_tc_record_t);

                            if (rec.name && rec.name->u8_bytes > 0) {
                                type_sym = n00b_symtab_lookup_any(ar->symtab,
                                                                  n00b_string_empty(),
                                                                  rec.name);
                            }
                        }
                    }

                    // Fallback: look up the variable, check user_data.
                    if (!type_sym) {
                        n00b_parse_tree_t *var_tok = n00b_pt_first_token(lhs_node);

                        if (var_tok) {
                            const char *vn = n00b_pt_token_text(var_tok);
                            size_t      vl = n00b_pt_token_text_len(var_tok);

                            if (vn && vl > 0) {
                                n00b_string_t    *vstr = n00b_string_from_raw(vn, (int64_t)vl);
                                n00b_sym_entry_t *var_sym
                                    = n00b_symtab_lookup_any(ar->symtab,
                                                             n00b_string_empty(),
                                                             vstr);

                                if (var_sym && var_sym->type_var) {
                                    n00b_tc_type_t *root = n00b_tc_find(var_sym->type_var);

                                    if (root->user_data) {
                                        type_sym = (n00b_sym_entry_t *)root->user_data;
                                    }
                                }
                            }
                        }
                    }

                    // Fallback for `self`: inside a method, derive
                    // the class name from the current function name
                    // (mangled as ClassName$methodName).
                    if (!type_sym) {
                        n00b_parse_tree_t *var_tok = n00b_pt_first_token(lhs_node);

                        if (var_tok) {
                            const char *vn = n00b_pt_token_text(var_tok);
                            size_t      vl = n00b_pt_token_text_len(var_tok);

                            if (vn && vl == 4 && memcmp(vn, "self", 4) == 0) {
                                n00b_cg_module_t *m = s->active_module;

                                if (m && m->cur_func) {
                                    const char *fname  = m->cur_func->u.func->name;
                                    const char *dollar = strchr(fname, '$');

                                    if (dollar) {
                                        size_t         clen = (size_t)(dollar - fname);
                                        n00b_string_t *cname
                                            = n00b_string_from_raw(fname, (int64_t)clen);
                                        type_sym = n00b_symtab_lookup_any(ar->symtab,
                                                                          n00b_string_empty(),
                                                                          cname);
                                    }
                                }
                            }
                        }
                    }

                    if (type_sym && type_sym->exposed_scope) {
                        if (!type_sym->class_layout) {
                            type_sym->class_layout
                                = compute_class_layout(s, type_sym->exposed_scope);
                        }
                        layout = type_sym->class_layout;
                    }

                    if (!layout) {
                        n00b_parse_tree_t *var_tok = n00b_pt_first_token(lhs_node);

                        if (var_tok) {
                            const char *vn = n00b_pt_token_text(var_tok);
                            size_t      vl = n00b_pt_token_text_len(var_tok);

                            if (vn && vl > 0) {
                                char *vname = codegen_dup_raw_text(vn, vl);
                                layout      = codegen_lookup_local_layout(s, vname);
                            }
                        }
                    }

                    if (layout) {
                        int32_t fidx = layout_field_index(layout, rhs_name, rhs_len);

                        if (fidx >= 0) {
                            n00b_cg_type_tag_t get_pt[] = {N00B_CG_I64, N00B_CG_I64};
                            n00b_cg_import_func(s,
                                                "n00b_builtin_field_get",
                                                (void *)n00b_builtin_field_get,
                                                .ret         = N00B_CG_I64,
                                                .param_types = get_pt,
                                                .n_params    = 2);
                            n00b_cg_val_t offset_arg
                                = _n00b_cg_const_i64(s, (int64_t)layout->field_offsets[fidx]);
                            n00b_cg_val_t get_args[] = {obj_val, offset_arg};
                            return n00b_cg_emit_call(s,
                                                     "n00b_builtin_field_get",
                                                     get_args,
                                                     2,
                                                     .ret = N00B_CG_I64);
                        }
                    }

                    // Third try: property-style extension method dispatch
                    // (`obj.foo` with no parens). After the enum and
                    // class-field paths have failed, ask the type
                    // registry whether the receiver's type has an
                    // extension method matching `rhs_name`. If found,
                    // emit an indirect call to the registered function
                    // pointer with the receiver as the sole argument and
                    // tag the result with the method's declared return
                    // type. This is the WP-010 hook.
                    {
                        uint64_t recv_hash
                            = n00b_cg_val_get_type_hash(s, obj_val);

                        if (recv_hash) {
                            // Null-terminate the identifier so the C-string
                            // lookup against the registry's interned names
                            // succeeds. `rhs_name` points into the token
                            // text and is not guaranteed terminated.
                            char *mname = n00b_alloc_array(char, rhs_len + 1);
                            memcpy(mname, rhs_name, rhs_len);
                            mname[rhs_len] = '\0';

                            n00b_cg_val_t method_args[1] = {obj_val};
                            n00b_cg_val_t method_result;

                            if (n00b_codegen_method_dispatch(s,
                                                             mname,
                                                             method_args,
                                                             1,
                                                             &method_result)) {
                                return method_result;
                            }
                        }
                    }
                }
            }
        }
    }

    // Check rule annotations for semantic info.
    if (s->grammar && pn->id >= 0) {
        n00b_parse_rule_t *rule = n00b_get_node_rule(s->grammar, pn);

        if (rule && n00b_list_len(rule->annotations) > 0) {
            size_t n_annots = n00b_list_len(rule->annotations);

            for (size_t i = 0; i < n_annots; i++) {
                n00b_annotation_t *a = n00b_list_get(rule->annotations, i);

                if (!a) {
                    continue;
                }

                switch (a->kind) {
                case N00B_ANNOT_OPERATOR:
                    return codegen_operator(s, node);
                case N00B_ANNOT_LITERAL:
                    return codegen_literal(s, node, a);
                case N00B_ANNOT_CALL:
                    return codegen_call_auto(s, node, a);
                default:
                    break;
                }
            }
        }

        // Also check NT-level pending annotations.
        n00b_nonterm_t *nt = n00b_get_nonterm(s->grammar, pn->id);

        if (nt && n00b_list_len(nt->pending_annotations) > 0) {
            size_t n_annots = n00b_list_len(nt->pending_annotations);

            for (size_t i = 0; i < n_annots; i++) {
                n00b_annotation_t *a = n00b_list_get(nt->pending_annotations, i);

                if (!a) {
                    continue;
                }

                switch (a->kind) {
                case N00B_ANNOT_OPERATOR:
                    return codegen_operator(s, node);
                case N00B_ANNOT_LITERAL:
                    return codegen_literal(s, node, a);
                case N00B_ANNOT_CALL:
                    return codegen_call_auto(s, node, a);
                default:
                    break;
                }
            }
        }
    }

    // Auto-detect operator nodes.
    {
        size_t nc           = n00b_pt_num_children(node);
        int    n_tok        = 0;
        int    n_nt         = 0;
        bool   has_known_op = false;

        for (size_t i = 0; i < nc; i++) {
            n00b_parse_tree_t *child = n00b_pt_get_child(node, i);

            if (n00b_pt_is_token(child)) {
                n_tok++;

                if (n_tok == 1) {
                    const char *text = n00b_pt_token_text(child);
                    size_t      tlen = n00b_pt_token_text_len(child);

                    if (text && tlen > 0 && tlen < sizeof(char[32])) {
                        char buf[32];
                        memcpy(buf, text, tlen);
                        buf[tlen] = '\0';

                        if (n00b_cg_lookup_op(s, buf) >= 0) {
                            has_known_op = true;
                        }
                    }
                }
            }
            else if (!n00b_pt_is_group(child)) {
                n_nt++;
            }
        }

        if (has_known_op && n_tok == 1 && (n_nt == 1 || n_nt == 2)) {
            return codegen_operator(s, node);
        }
    }

    // Check for embed literal.
    // Embed tokens have tok->modifier set (the 'ffi suffix) or are
    // identifiable by their grammar terminal name "EMBED".
    // We check tok->modifier since that's specific to embed literals.
    if (n00b_pt_is_nt(node, "simple-lit")) {
        n00b_parse_tree_t *first = n00b_pt_first_token(node);

        if (first) {
            n00b_token_info_t *tok = n00b_parse_node_token(first);

            if (codegen_token_is_terminal(s, tok, "EMBED")) {
                return codegen_embed(s, node);
            }
        }
    }

    // Default handler.
    if (s->default_handler) {
        return s->default_handler(s, node);
    }

    // Fall through: lower all children.
    return codegen_children_default(s, node);
}

// ============================================================================
// Public emission entry point
// ============================================================================

n00b_cg_val_t
n00b_codegen_lower(n00b_cg_session_t *s, n00b_parse_tree_t *child)
{
    return codegen_walk(s, child);
}

bool
n00b_codegen_emit(n00b_cg_session_t *s, n00b_parse_tree_t *tree)
{
    if (!tree) {
        return false;
    }

    codegen_walk(s, tree);

    return !s->has_codegen_errors && !n00b_diag_has_errors(s->diag);
}

// ============================================================================
// Pre-flight audit
// ============================================================================

n00b_cg_audit_t
n00b_codegen_audit(n00b_cg_session_t *s)
{
    n00b_cg_audit_t result = {0};

    if (!s->grammar) {
        return result;
    }

    int64_t nt_count = (int64_t)n00b_list_len(s->grammar->nt_list);

    if (nt_count == 0) {
        return result;
    }

    const char **unhandled    = n00b_alloc_array(const char *, (size_t)nt_count);
    const char **auto_infer   = n00b_alloc_array(const char *, (size_t)nt_count);
    const char **explicit_arr = n00b_alloc_array(const char *, (size_t)nt_count);

    int32_t uh_count = 0;
    int32_t ai_count = 0;
    int32_t ex_count = 0;

    for (int64_t id = 0; id < nt_count; id++) {
        n00b_nonterm_t *nt = n00b_get_nonterm(s->grammar, id);

        if (!nt) {
            continue;
        }

        const char *name = nt->name ? nt->name->data : NULL;

        if (!name) {
            continue;
        }

        if (nt->group_nt) {
            continue;
        }

        if (name[0] == '$' && name[1] == '$') {
            continue;
        }

        if (s->handlers && id < s->handler_cap && s->handlers[id]) {
            explicit_arr[ex_count++] = name;
            continue;
        }

        bool has_semantic = false;

        if (n00b_list_len(nt->pending_annotations) > 0) {
            size_t na = n00b_list_len(nt->pending_annotations);

            for (size_t i = 0; i < na; i++) {
                n00b_annotation_t *a = n00b_list_get(nt->pending_annotations, i);

                if (a && annot_is_semantic(a->kind)) {
                    has_semantic = true;
                    break;
                }
            }
        }

        if (!has_semantic) {
            size_t n_rules = n00b_list_len(nt->rule_ids);

            for (size_t ri = 0; ri < n_rules && !has_semantic; ri++) {
                int32_t            gix  = n00b_list_get(nt->rule_ids, ri);
                n00b_parse_rule_t *rule = n00b_get_rule(s->grammar, gix);

                if (!rule) {
                    continue;
                }

                size_t na = n00b_list_len(rule->annotations);

                for (size_t ai = 0; ai < na; ai++) {
                    n00b_annotation_t *a = n00b_list_get(rule->annotations, ai);

                    if (a && annot_is_semantic(a->kind)) {
                        has_semantic = true;
                        break;
                    }
                }
            }
        }

        if (has_semantic) {
            auto_infer[ai_count++] = name;
            continue;
        }

        bool only_format = true;

        if (n00b_list_len(nt->pending_annotations) > 0) {
            size_t na = n00b_list_len(nt->pending_annotations);

            for (size_t i = 0; i < na; i++) {
                n00b_annotation_t *a = n00b_list_get(nt->pending_annotations, i);

                if (a && !annot_is_format_only(a->kind) && a->kind != N00B_ANNOT_NONE) {
                    only_format = false;
                    break;
                }
            }
        }

        if (only_format && n00b_list_len(nt->pending_annotations) > 0) {
            continue;
        }

        unhandled[uh_count++] = name;
    }

    result.unhandled_nts       = unhandled;
    result.unhandled_count     = uh_count;
    result.auto_inferred       = auto_infer;
    result.auto_inferred_count = ai_count;
    result.explicit_handled    = explicit_arr;
    result.explicit_count      = ex_count;

    return result;
}

void
n00b_cg_audit_free(n00b_cg_audit_t *audit)
{
    if (audit) {
        audit->unhandled_nts       = NULL;
        audit->auto_inferred       = NULL;
        audit->explicit_handled    = NULL;
        audit->unhandled_count     = 0;
        audit->auto_inferred_count = 0;
        audit->explicit_count      = 0;
    }
}

// ============================================================================
// Execution modes (backward compat — operate on first module)
// ============================================================================

static void
ensure_linked(n00b_cg_session_t *s, bool for_gen)
{
    n00b_cg_module_t *m = s->active_module;

    if (!m) {
        return;
    }

    codegen_resolve_runtime_callbacks(s);

    // Already linked or compiled — nothing to do.
    if (m->state >= N00B_CG_MOD_LINKED) {
        return;
    }

    if (m->state == N00B_CG_MOD_BUILDING) {
        MIR_finish_module(s->mir_ctx);
        m->state = N00B_CG_MOD_FINISHED;
    }

    codegen_resolve_runtime_callbacks(s);
    codegen_report_unresolved_runtime_callbacks(s);

    if (s->has_codegen_errors) {
        return;
    }

    MIR_load_module(s->mir_ctx, m->mir_module);

    // Resolve per-module imports.
    for (int32_t i = 0; i < m->import_count; i++) {
        MIR_load_external(s->mir_ctx, m->imports[i].name, m->imports[i].addr);
    }

    if (for_gen) {
        if (!s->gen_inited) {
            MIR_gen_init(s->mir_ctx);
            s->gen_inited = true;
        }
        MIR_link(s->mir_ctx, MIR_set_gen_interface, NULL);
    }
    else {
        MIR_link(s->mir_ctx, MIR_set_interp_interface, NULL);
    }

    m->state = N00B_CG_MOD_LINKED;
}

bool
n00b_codegen_interpret(n00b_cg_session_t *s,
                       const char        *func_name,
                       void              *result,
                       void              *args,
                       int32_t            n_args)
{
    ensure_linked(s, false);

    MIR_item_t func = n00b_cg_find_func(s, func_name);

    if (!func) {
        return false;
    }

    MIR_val_t  res;
    MIR_val_t *arg_vals = (MIR_val_t *)args;

    if (n_args > 0 && arg_vals) {
        MIR_interp_arr(s->mir_ctx, func, &res, (size_t)n_args, arg_vals);
    }
    else {
        MIR_interp(s->mir_ctx, func, &res, 0);
    }

    if (result) {
        memcpy(result, &res, sizeof(MIR_val_t));
    }

    return true;
}

void *
n00b_codegen_jit(n00b_cg_session_t *s, const char *func_name)
{
    ensure_linked(s, true);

    MIR_item_t func = n00b_cg_find_func(s, func_name);

    if (!func) {
        return NULL;
    }

    return MIR_gen(s->mir_ctx, func);
}

void
n00b_codegen_dump(n00b_cg_session_t *s, FILE *f)
{
    MIR_output(s->mir_ctx, f);
}

void
n00b_cg_session_dump(n00b_cg_session_t *s, FILE *out)
{
    MIR_output(s->mir_ctx, out);
}

// ============================================================================
// Convenience helpers
// ============================================================================

bool
n00b_cg_emit_func_from_tree(n00b_cg_session_t *s,
                            n00b_parse_tree_t *tree,
                            const char        *func_name) _kargs
{
    n00b_cg_type_tag_t ret;
}
{
    if (!s || !tree || !func_name) {
        return false;
    }

    n00b_cg_type_tag_t ret_type = kargs->ret;

    // Treat unset (0) as I64 since that's the most common REPL use case.
    if (ret_type == 0) {
        ret_type = N00B_CG_I64;
    }

    n00b_cg_type_tag_t saved_ret_type = s->current_func_ret_type;
    s->current_func_ret_type          = ret_type;

    n00b_cg_begin_func(s, func_name, .ret = ret_type);

    bool saved_reject = s->reject_unconsumed_yield;
    s->reject_unconsumed_yield = true;
    n00b_cg_val_t result       = n00b_codegen_lower(s, tree);
    s->reject_unconsumed_yield = saved_reject;

    // Report the type of the last expression to the caller.
    if (kargs->result_type) {
        *kargs->result_type
            = (result.kind != N00B_CG_VAL_VOID) ? result.type_tag : N00B_CG_VOID;
    }

    if (result.kind != N00B_CG_VAL_VOID) {
        n00b_cg_emit_ret(s, result);
    }
    else if (ret_type == N00B_CG_VOID) {
        n00b_cg_emit_ret_void(s);
    }
    else {
        n00b_cg_emit_ret(s, _n00b_cg_const_i64(s, 0));
    }

    s->current_func_ret_type = saved_ret_type;
    n00b_cg_end_func(s);

    return !s->has_codegen_errors && !n00b_diag_has_errors(s->diag);
}

int64_t
n00b_codegen_eval_tree(n00b_grammar_t *grammar, n00b_parse_tree_t *tree) _kargs
{
    n00b_annot_result_t *annot;
    n00b_cg_type_map_fn  type_map;
    const char          *func_name;
    bool                *ok;
}
{
    if (kargs->ok) {
        *kargs->ok = false;
    }

    if (!tree) {
        return 0;
    }

    const char *fname = kargs->func_name ? kargs->func_name : "_eval";

    n00b_codegen_t *cg
        = n00b_codegen_new(grammar, .annot = kargs->annot, .type_map = kargs->type_map);

    bool emit_ok = n00b_cg_emit_func_from_tree(cg, tree, fname, .ret = N00B_CG_I64);

    if (!emit_ok) {
        n00b_codegen_free(cg);
        return 0;
    }

    typedef int64_t (*eval_fn_t)(void);

    eval_fn_t fn = (eval_fn_t)n00b_codegen_jit(cg, fname);

    if (!fn) {
        n00b_codegen_free(cg);
        return 0;
    }

    int64_t val = fn();

    if (kargs->ok) {
        *kargs->ok = true;
    }

    n00b_codegen_free(cg);

    return val;
}

// ============================================================================
// Cross-module symbol resolution
// ============================================================================

void
n00b_cg_session_merge_module(n00b_cg_session_t *s, n00b_cg_module_t *m)
{
    if (!s || !m || !m->annot || !m->annot->symtab) {
        return;
    }

    n00b_symtab_t    *src = m->annot->symtab;
    n00b_namespace_t *ns  = n00b_symtab_ns(src, n00b_string_empty());

    if (!ns || !ns->all_scopes) {
        return;
    }

    // Walk top-level scopes (depth 0) looking for public functions.
    for (int32_t si = 0; si < ns->all_count; si++) {
        n00b_scope_t *scope = ns->all_scopes[si];

        if (!scope || scope->depth != 0) {
            continue;
        }

        n00b_sym_entry_t *sym;
        for (sym = scope->first_in_scope; sym; sym = sym->next_in_scope) {
            if (sym->kind != N00B_SYM_FUNCTION) {
                continue;
            }

            if ((sym->visibility && sym->visibility->u8_bytes == 7
                 && memcmp(sym->visibility->data, "private", 7) == 0)
                || codegen_func_decl_has_modifier(sym->decl_node, "private")) {
                continue;
            }

            n00b_symtab_add(s->global_scope,
                            n00b_string_empty(),
                            sym->name,
                            N00B_SYM_FUNCTION,
                            sym->decl_node);
        }
    }
}

n00b_sym_entry_t *
n00b_cg_module_lookup(n00b_cg_module_t *m, const char *name)
{
    if (!m || !name) {
        return NULL;
    }

    // Try module's own symtab first.
    if (m->annot && m->annot->symtab) {
        n00b_string_t    *sname = n00b_string_from_cstr(name);
        n00b_sym_entry_t *sym
            = n00b_symtab_lookup_any(m->annot->symtab, n00b_string_empty(), sname);

        if (sym) {
            return sym;
        }
    }

    // Fall back to session global scope.
    if (m->session && m->session->global_scope) {
        n00b_string_t *sname = n00b_string_from_cstr(name);

        return n00b_symtab_lookup_any(m->session->global_scope, n00b_string_empty(), sname);
    }

    return NULL;
}

n00b_cg_module_t *
n00b_cg_session_find_module(n00b_cg_session_t *s, const char *fqn)
{
    if (!s || !fqn || !s->module_cache) {
        return NULL;
    }

    bool  found = false;
    void *val   = n00b_dict_untyped_get(s->module_cache, fqn, &found);

    return found ? (n00b_cg_module_t *)val : NULL;
}

// ============================================================================
// Session eval tree (new API)
// ============================================================================

int64_t
n00b_cg_session_eval_tree(n00b_cg_session_t *s, n00b_parse_tree_t *tree) _kargs
{
    n00b_annot_result_t *annot;
    const char          *func_name;
    bool                *ok;
}
{
    if (kargs->ok) {
        *kargs->ok = false;
    }

    if (!tree || !s) {
        return 0;
    }

    // Generate a unique module name.
    const char *mod_name = n00b_unicode_str_to_cstr(
        n00b_cformat("repl_[|#|]", (int64_t)s->module_count));

    const char *fname = kargs->func_name ? kargs->func_name : "_eval";

    // Create a new module for this expression.
    n00b_cg_module_t *m = n00b_cg_module_new(s, mod_name);

    // Set annotation result on the module.
    if (kargs->annot) {
        m->annot = kargs->annot;
    }

    // Emit the tree as a function.
    n00b_cg_type_tag_t last_type = N00B_CG_VOID;
    bool               emit_ok   = n00b_cg_emit_func_from_tree(s,
                                               tree,
                                               fname,
                                               .ret         = N00B_CG_I64,
                                               .result_type = &last_type);

    if (kargs->out_type) {
        *kargs->out_type = last_type;
    }

    if (!emit_ok) {
        return 0;
    }

    // Compile the module and get entry function pointer.
    typedef int64_t (*eval_fn_t)(void);

    eval_fn_t fn = (eval_fn_t)n00b_cg_module_compile(m, fname);

    // Merge public symbols so later expressions can see them.
    n00b_cg_session_merge_module(s, m);

    if (!fn) {
        return 0;
    }

    int64_t val = fn();

    if (kargs->ok) {
        *kargs->ok = true;
    }

    return val;
}

// ============================================================================
// Import table management
// ============================================================================

n00b_cg_import_table_t *
n00b_cg_import_table_new(void)
{
    n00b_cg_import_table_t *t = n00b_alloc(n00b_cg_import_table_t);

    t->cap     = 32;
    t->count   = 0;
    t->entries = n00b_alloc_array(n00b_cg_import_entry_t, 32);

    return t;
}

void
n00b_cg_import_table_add(n00b_cg_import_table_t *table, n00b_cg_import_entry_t entry)
{
    if (table->count >= table->cap) {
        int32_t                 new_cap = table->cap * 2;
        n00b_cg_import_entry_t *new_entries
            = n00b_alloc_array(n00b_cg_import_entry_t, (size_t)new_cap);
        memcpy(new_entries,
               table->entries,
               sizeof(n00b_cg_import_entry_t) * (size_t)table->count);
        table->entries = new_entries;
        table->cap     = new_cap;
    }

    table->entries[table->count++] = entry;
}

void
n00b_cg_import_table_free(n00b_cg_import_table_t *table)
{
    // GC-allocated, nothing to do explicitly.
    (void)table;
}

void
n00b_cg_import_table_resolve_types(n00b_cg_import_table_t *table, n00b_tc_ctx_t *ctx)
{
    if (!table || !ctx) {
        return;
    }

    for (int32_t i = 0; i < table->count; i++) {
        n00b_cg_import_entry_t *e = &table->entries[i];

        if (e->type_builder && !e->resolved_type) {
            e->resolved_type = e->type_builder(ctx);
        }
    }
}

static int64_t
codegen_nt_id(n00b_cg_session_t *s, const char *name)
{
    if (!s || !s->grammar || !name) {
        return -1;
    }

    bool           found   = false;
    n00b_string_t *nt_name = n00b_string_from_cstr(name);
    int64_t        nt_id   = n00b_dict_get(s->grammar->nt_map, nt_name, &found);

    return found ? nt_id : -1;
}

static void
codegen_prescan_top_level_decls(n00b_cg_session_t *s, n00b_parse_tree_t *tree)
{
    int64_t func_def_nt_id = codegen_nt_id(s, "func-def");
    int64_t comptime_nt_id = codegen_nt_id(s, "comptime-stmt");
    int64_t extern_nt_id   = codegen_nt_id(s, "extern-block");

    n00b_parse_tree_t *stack[256];
    int                sp = 0;

    stack[sp++] = tree;

    while (sp > 0) {
        n00b_parse_tree_t *cur = stack[--sp];

        if (!cur || n00b_pt_is_token(cur)) {
            continue;
        }

        n00b_nt_node_t *pn = &n00b_tree_node_value(cur);

        if (pn->id == func_def_nt_id) {
            codegen_walk(s, cur);
            continue;
        }

        if (pn->id == comptime_nt_id) {
            codegen_comptime(s, cur);
            continue;
        }

        if (pn->id == extern_nt_id) {
            codegen_extern_block(s, cur);
            continue;
        }

        size_t nc = n00b_pt_num_children(cur);

        for (size_t i = nc; i > 0; i--) {
            n00b_parse_tree_t *child = n00b_pt_get_child(cur, i - 1);

            if (sp < 256) {
                stack[sp++] = child;
            }
        }
    }
}

// ============================================================================
// Module-level run: two-pass codegen for whole-file execution
// ============================================================================

int64_t
n00b_cg_session_run_module(n00b_cg_session_t *s, n00b_parse_tree_t *tree) _kargs
{
    n00b_annot_result_t *annot;
    const char          *entry_name;
    bool                *ok;
}
{
    if (kargs->ok) {
        *kargs->ok = false;
    }

    if (!tree || !s) {
        return 0;
    }

    const char *entry = kargs->entry_name ? kargs->entry_name : "_main";

    // Create a new module.
    const char *mod_name = n00b_unicode_str_to_cstr(
        n00b_cformat("mod_[|#|]", (int64_t)s->module_count));

    n00b_cg_module_t *m = n00b_cg_module_new(s, mod_name);

    if (kargs->annot) {
        m->annot = kargs->annot;
    }

    // Pass 1: emit top-level functions, comptime blocks, and extern declarations.
    codegen_prescan_top_level_decls(s, tree);

    // --- Pass 2: wrap all top-level statements in _main ---
    // codegen_func_def will see cur_func != NULL and return VOID,
    // skipping already-emitted function definitions.
    bool emit_ok = n00b_cg_emit_func_from_tree(s, tree, entry, .ret = N00B_CG_I64);

    if (!emit_ok) {
        return 0;
    }

    // Compile the module and get entry function pointer.
    typedef int64_t (*entry_fn_t)(void);

    entry_fn_t fn = (entry_fn_t)n00b_cg_module_compile(m, entry);

    // Merge public symbols.
    n00b_cg_session_merge_module(s, m);

    if (!fn) {
        return 0;
    }

    int64_t val = fn();

    if (kargs->ok) {
        *kargs->ok = true;
    }

    return val;
}

// ============================================================================
// AOT compilation: extract machine code without executing
// ============================================================================

n00b_module_code_t *
n00b_cg_session_compile_module(n00b_cg_session_t *s, n00b_parse_tree_t *tree) _kargs
{
    n00b_annot_result_t *annot;
    const char          *entry_name;
}
{
#ifdef _WIN32
    (void)s;
    (void)tree;
    return NULL;
#endif

    if (!tree || !s) {
        return NULL;
    }

    const char *entry = kargs->entry_name ? kargs->entry_name : "_main";

    // Create a new module.
    const char *mod_name = n00b_unicode_str_to_cstr(
        n00b_cformat("mod_[|#|]", (int64_t)s->module_count));

    n00b_cg_module_t *m = n00b_cg_module_new(s, mod_name);

    if (kargs->annot) {
        m->annot = kargs->annot;
    }

    // Pass 1: emit top-level functions, comptime blocks, and extern declarations.
    codegen_prescan_top_level_decls(s, tree);

    // --- Pass 2: wrap remaining statements in _main ---
    bool emit_ok = n00b_cg_emit_func_from_tree(s, tree, entry, .ret = N00B_CG_I64);

    if (!emit_ok) {
        return NULL;
    }

    // Count functions before linking because MIR_set_gen_interface emits all
    // machine code during MIR_link().
    size_t func_count = 0;

    MIR_item_t item;
    for (item = DLIST_HEAD(MIR_item_t, m->mir_module->items); item != NULL;
         item = DLIST_NEXT(MIR_item_t, item)) {
        if (item->item_type == MIR_func_item) {
            func_count++;
        }
    }

    if (func_count == 0) {
        return NULL;
    }

    size_t *code_lens  = n00b_alloc_array(size_t, func_count);
    FILE   *code_trace = n00b_mir_open_code_len_trace();

    // Compile the module (finish, load, link, but don't execute).
    // Pass NULL entry to compile all functions without returning a pointer.
    n00b_cg_module_compile_traced(m, NULL, code_trace);

    if (!n00b_mir_finish_code_len_trace(s->mir_ctx, code_trace, code_lens, func_count)) {
        n00b_free(code_lens);
        return NULL;
    }

    // Collect import symbol names and their resolved addresses for
    // relocation scanning.
    size_t       import_count = 0;
    const char **import_names = NULL;
    void       **import_addrs = NULL;

    for (item = DLIST_HEAD(MIR_item_t, m->mir_module->items); item != NULL;
         item = DLIST_NEXT(MIR_item_t, item)) {
        if (item->item_type == MIR_import_item) {
            import_count++;
        }
    }

    if (import_count > 0) {
        import_names = n00b_alloc_array(const char *, import_count);
        import_addrs = n00b_alloc_array(void *, import_count);
        size_t idx   = 0;

        for (item = DLIST_HEAD(MIR_item_t, m->mir_module->items); item != NULL;
             item = DLIST_NEXT(MIR_item_t, item)) {
            if (item->item_type == MIR_import_item) {
                import_names[idx] = item->u.import_id;
                import_addrs[idx] = item->addr;
                idx++;
            }
        }
    }

    // Allocate result.
    n00b_module_code_t *result = n00b_alloc(n00b_module_code_t);

    result->module_name = mod_name;
    result->func_count  = func_count;
    result->funcs       = n00b_alloc_array(n00b_func_code_t, func_count);

    // Extract machine code and relocations for each generated function.
    size_t fi = 0;

    for (item = DLIST_HEAD(MIR_item_t, m->mir_module->items); item != NULL;
         item = DLIST_NEXT(MIR_item_t, item)) {
        if (item->item_type != MIR_func_item) {
            continue;
        }

        size_t     code_len = code_lens[fi];
        MIR_func_t func     = item->u.func;

        if (!func->machine_code || code_len == 0) {
            n00b_free(result->funcs);
            n00b_free(result);
            n00b_free(code_lens);
            n00b_free(import_names);
            n00b_free(import_addrs);
            return NULL;
        }

        result->funcs[fi].name     = func->name;
        result->funcs[fi].code     = (uint8_t *)func->machine_code;
        result->funcs[fi].code_len = code_len;

        // Scan machine code for references to import addresses.
        // On x86_64/aarch64, external addresses appear as 8-byte
        // absolute values in the code or const pool.
        size_t        max_relocs  = import_count;
        n00b_reloc_t *relocs      = NULL;
        size_t        reloc_count = 0;

        if (import_count > 0 && code_len >= 8) {
            relocs        = n00b_alloc_array(n00b_reloc_t, max_relocs);
            uint8_t *code = (uint8_t *)func->machine_code;

            for (size_t off = 0; off <= code_len - 8; off++) {
                uint64_t val;
                memcpy(&val, code + off, 8);

                for (size_t j = 0; j < import_count; j++) {
                    if (val == (uint64_t)(uintptr_t)import_addrs[j]) {
                        // Found a reference to an imported symbol.
                        if (reloc_count >= max_relocs) {
                            size_t        old_max = max_relocs;
                            max_relocs *= 2;
                            n00b_reloc_t *grown = n00b_alloc_array(n00b_reloc_t,
                                                                   max_relocs);
                            memcpy(grown, relocs, old_max * sizeof(n00b_reloc_t));
                            n00b_free(relocs);
                            relocs = grown;
                        }
                        relocs[reloc_count].sym    = import_names[j];
                        relocs[reloc_count].offset = off;
                        reloc_count++;
                        off += 7; // Skip past this address.
                        break;
                    }
                }
            }
        }

        result->funcs[fi].relocs      = relocs;
        result->funcs[fi].reloc_count = reloc_count;
        fi++;
    }

    // Merge public symbols so subsequent modules can see them.
    n00b_cg_session_merge_module(s, m);

    n00b_free(code_lens);
    n00b_free(import_names);
    n00b_free(import_addrs);

    return result;
}

// Platform-specific section boundary declarations.
#ifdef __APPLE__
extern const n00b_cg_import_entry_t __start_n00b_ffi[]
    __asm("section$start$__DATA$n00b_ffi")
    __attribute__((weak));
extern const n00b_cg_import_entry_t __stop_n00b_ffi[]
    __asm("section$end$__DATA$n00b_ffi")
    __attribute__((weak));
#else
extern const n00b_cg_import_entry_t __start_n00b_ffi[]
    __attribute__((weak));
extern const n00b_cg_import_entry_t __stop_n00b_ffi[]
    __attribute__((weak));
#endif

n00b_cg_import_table_t *
n00b_cg_collect_exports(void)
{
    n00b_cg_import_table_t *table = n00b_cg_import_table_new();
    const n00b_cg_import_entry_t *start = __start_n00b_ffi;
    const n00b_cg_import_entry_t *stop  = __stop_n00b_ffi;

    if (start == NULL || stop == NULL || start >= stop) {
        return table;
    }

    if (!start || !stop) {
        return table;
    }

    const n00b_cg_import_entry_t *e;
    for (e = start; e < stop; e++) {
        if (e->name && e->addr) {
            n00b_cg_import_table_add(table, *e);
        }
    }

    return table;
}
