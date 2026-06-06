// transform.c — Tree transform framework for slay parse trees.
//
// Provides:
//  - Registry-based pre/post-order tree transformer
//  - Tree mutation primitives (set/remove/insert child, clone)
//  - Node construction helpers (make NT, make token, make with children)
//  - Stack-based iterative tree walker

#include "slay/transform.h"
#include "slay/n00b_parse.h"
#include "internal/slay/grammar_internal.h"
#include "parsers/token_stream.h"
#include "parsers/tokenizer_registry.h"
#include "core/alloc.h"
#include "core/buffer.h"

#include <assert.h>
#include <string.h>

// ============================================================================
// Internal: NT id lookup by name
// ============================================================================

static int64_t
nt_id_for_name(n00b_grammar_t *grammar, const char *nt_name)
{
    if (!grammar || !nt_name) {
        return -1;
    }

    n00b_string_t *s = n00b_string_from_cstr(nt_name);
    n00b_nonterm_t *nt = n00b_nonterm(grammar, s);

    if (!nt) {
        return -1;
    }

    return n00b_nonterm_id(nt);
}

// ============================================================================
// Tree mutation primitives
// ============================================================================

bool
n00b_xform_set_child(n00b_parse_tree_t *parent, size_t index,
                      n00b_parse_tree_t *new_child)
{
    return n00b_tree_set_child(parent, index, new_child);
}

n00b_parse_tree_t *
n00b_xform_remove_child(n00b_parse_tree_t *parent, size_t index)
{
    return n00b_tree_remove_child(parent, index);
}

bool
n00b_xform_insert_child(n00b_parse_tree_t *parent, size_t index,
                          n00b_parse_tree_t *child)
{
    return n00b_tree_insert_child_at(parent, index, child);
}

n00b_parse_tree_t *
n00b_xform_clone(n00b_parse_tree_t *tree)
{
    if (!tree) {
        return NULL;
    }

    if (n00b_tree_is_leaf(tree)) {
        n00b_token_info_t *orig_tok = n00b_tree_leaf_value(tree);

        // Allocate a copy of the token info.
        n00b_token_info_t *tok_copy = n00b_alloc(n00b_token_info_t);

        if (tok_copy && orig_tok) {
            *tok_copy = *orig_tok;
            // n00b_string_t value is GC-managed, shallow copy is fine.
        }

        return n00b_tree_leaf(n00b_nt_node_t, n00b_token_info_t *, tok_copy);
    }

    n00b_nt_node_t pn = n00b_tree_node_value(tree);
    // n00b_string_t name is GC-managed, shallow copy is fine.

    n00b_parse_tree_t *copy = n00b_tree_node(n00b_nt_node_t,
                                               n00b_token_info_t *, pn);

    size_t nch = n00b_tree_num_children(tree);

    for (size_t i = 0; i < nch; i++) {
        n00b_parse_tree_t *child_copy = n00b_xform_clone(
            n00b_tree_child(tree, i));
        (void)n00b_tree_add_child(copy, child_copy);
    }

    return copy;
}

// ============================================================================
// Node construction helpers
// ============================================================================

n00b_parse_tree_t *
n00b_xform_make_nt_node(n00b_grammar_t *grammar, const char *nt_name,
                          int32_t rule_index)
{
    n00b_nt_node_t pn = {0};

    if (nt_name) {
        pn.name = n00b_string_from_cstr(nt_name);
    }

    pn.rule_index = rule_index;
    pn.id         = nt_id_for_name(grammar, nt_name);

    return n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, pn);
}

n00b_parse_tree_t *
n00b_xform_make_token_node(int64_t tid, const char *value,
                             uint32_t line, uint32_t col)
{
    n00b_token_info_t *tok = n00b_alloc(n00b_token_info_t);

    if (!tok) {
        return NULL;
    }

    memset(tok, 0, sizeof(*tok));
    tok->tid    = tid;
    tok->line   = line;
    tok->column = col;

    if (value) {
        n00b_string_t *s = n00b_string_from_cstr(value);
        tok->value = n00b_option_set(n00b_string_t *, s);
    }
    else {
        tok->value = n00b_option_none(n00b_string_t *);
    }

    return n00b_tree_leaf(n00b_nt_node_t, n00b_token_info_t *, tok);
}

n00b_parse_tree_t *
n00b_xform_make_node_with_children(n00b_grammar_t     *grammar,
                                     const char         *nt_name,
                                     int32_t             rule_index,
                                     n00b_parse_tree_t **children,
                                     size_t              count)
{
    n00b_parse_tree_t *node = n00b_xform_make_nt_node(grammar, nt_name,
                                                        rule_index);
    if (!node) {
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        if (children[i]) {
            (void)n00b_tree_add_child(node, children[i]);
        }
    }

    return node;
}

// ============================================================================
// Registry
// ============================================================================

void
n00b_xform_registry_init(n00b_xform_registry_t *reg, n00b_grammar_t *grammar)
{
    assert(reg);
    memset(reg, 0, sizeof(*reg));
    reg->grammar = grammar;
}

void
n00b_xform_registry_free(n00b_xform_registry_t *reg)
{
    if (!reg) {
        return;
    }

    for (int i = 0; i < N00B_XFORM_MAX_DIRECT_NTS; i++) {
        if (reg->pre_order[i]) {
            for (int j = 0; j < reg->pre_count[i]; j++) {
                n00b_free(reg->pre_order[i][j]);
            }

            n00b_free(reg->pre_order[i]);
        }

        if (reg->post_order[i]) {
            for (int j = 0; j < reg->post_count[i]; j++) {
                n00b_free(reg->post_order[i][j]);
            }

            n00b_free(reg->post_order[i]);
        }
    }

    if (reg->wildcard_pre) {
        for (int i = 0; i < reg->wildcard_pre_count; i++) {
            n00b_free(reg->wildcard_pre[i]);
        }

        n00b_free(reg->wildcard_pre);
    }

    if (reg->wildcard_post) {
        for (int i = 0; i < reg->wildcard_post_count; i++) {
            n00b_free(reg->wildcard_post[i]);
        }

        n00b_free(reg->wildcard_post);
    }

    memset(reg, 0, sizeof(*reg));
}

// Internal: add an entry to a dynamic array.
static bool
add_entry(n00b_xform_entry_t ***array, int *count, int *cap,
          n00b_xform_entry_t   *entry)
{
    if (*count >= *cap) {
        int new_cap = *cap ? *cap * 2 : 4;
        n00b_xform_entry_t **new_arr = n00b_alloc_size(new_cap,
                                                         sizeof(n00b_xform_entry_t *));

        if (!new_arr) {
            return false;
        }

        if (*array && *count > 0) {
            memcpy(new_arr, *array,
                   (size_t)*count * sizeof(n00b_xform_entry_t *));
        }

        if (*array) {
            n00b_free(*array);
        }

        *array = new_arr;
        *cap   = new_cap;
    }

    (*array)[(*count)++] = entry;
    return true;
}

bool
n00b_xform_register(n00b_xform_registry_t *reg, const char *nt_name,
                      n00b_xform_fn_t fn, const char *name)
{
    assert(reg && fn);

    n00b_xform_entry_t *entry = n00b_alloc(n00b_xform_entry_t);

    if (!entry) {
        return false;
    }

    entry->post_fn = fn;
    entry->name    = name;
    entry->is_pre  = false;

    if (!nt_name) {
        return add_entry(&reg->wildcard_post,
                         &reg->wildcard_post_count,
                         &reg->wildcard_post_cap, entry);
    }

    int64_t id = nt_id_for_name(reg->grammar, nt_name);

    if (id >= 0 && id < N00B_XFORM_MAX_DIRECT_NTS) {
        return add_entry(&reg->post_order[id],
                         &reg->post_count[id],
                         &reg->post_cap[id], entry);
    }

    return add_entry(&reg->wildcard_post,
                     &reg->wildcard_post_count,
                     &reg->wildcard_post_cap, entry);
}

bool
n00b_xform_register_pre(n00b_xform_registry_t *reg, const char *nt_name,
                          n00b_xform_pre_fn_t fn, const char *name)
{
    assert(reg && fn);

    n00b_xform_entry_t *entry = n00b_alloc(n00b_xform_entry_t);

    if (!entry) {
        return false;
    }

    entry->pre_fn = fn;
    entry->name   = name;
    entry->is_pre = true;

    if (!nt_name) {
        return add_entry(&reg->wildcard_pre,
                         &reg->wildcard_pre_count,
                         &reg->wildcard_pre_cap, entry);
    }

    int64_t id = nt_id_for_name(reg->grammar, nt_name);

    if (id >= 0 && id < N00B_XFORM_MAX_DIRECT_NTS) {
        return add_entry(&reg->pre_order[id],
                         &reg->pre_count[id],
                         &reg->pre_cap[id], entry);
    }

    return add_entry(&reg->wildcard_pre,
                     &reg->wildcard_pre_count,
                     &reg->wildcard_pre_cap, entry);
}

bool
n00b_xform_register_by_id(n00b_xform_registry_t *reg, int64_t nt_id,
                            n00b_xform_fn_t fn, const char *name)
{
    assert(reg && fn);

    n00b_xform_entry_t *entry = n00b_alloc(n00b_xform_entry_t);

    if (!entry) {
        return false;
    }

    entry->post_fn = fn;
    entry->name    = name;
    entry->is_pre  = false;

    if (nt_id >= 0 && nt_id < N00B_XFORM_MAX_DIRECT_NTS) {
        return add_entry(&reg->post_order[nt_id],
                         &reg->post_count[nt_id],
                         &reg->post_cap[nt_id], entry);
    }

    return add_entry(&reg->wildcard_post,
                     &reg->wildcard_post_count,
                     &reg->wildcard_post_cap, entry);
}

bool
n00b_xform_register_pre_by_id(n00b_xform_registry_t *reg, int64_t nt_id,
                                n00b_xform_pre_fn_t fn, const char *name)
{
    assert(reg && fn);

    n00b_xform_entry_t *entry = n00b_alloc(n00b_xform_entry_t);

    if (!entry) {
        return false;
    }

    entry->pre_fn = fn;
    entry->name   = name;
    entry->is_pre = true;

    if (nt_id >= 0 && nt_id < N00B_XFORM_MAX_DIRECT_NTS) {
        return add_entry(&reg->pre_order[nt_id],
                         &reg->pre_count[nt_id],
                         &reg->pre_cap[nt_id], entry);
    }

    return add_entry(&reg->wildcard_pre,
                     &reg->wildcard_pre_count,
                     &reg->wildcard_pre_cap, entry);
}

// ============================================================================
// Context
// ============================================================================

void
n00b_xform_ctx_init(n00b_xform_ctx_t      *ctx,
                     n00b_grammar_t         *grammar,
                     n00b_xform_registry_t  *reg,
                     n00b_parse_tree_t      *root)
{
    assert(ctx);
    memset(ctx, 0, sizeof(*ctx));
    ctx->grammar  = grammar;
    ctx->registry = reg;
    ctx->root     = root;
}

// ============================================================================
// Internal: apply pre/post transformers to a single node
// ============================================================================

static n00b_parse_tree_t *
apply_pre(n00b_xform_registry_t *reg, n00b_xform_ctx_t *ctx,
          n00b_parse_tree_t *node, n00b_xform_control_t *control)
{
    *control = N00B_XFORM_CONTINUE;
    n00b_parse_tree_t *result = NULL;

    int64_t id = n00b_pt_nt_id(node);

    // Type-specific pre transforms.
    if (id >= 0 && id < N00B_XFORM_MAX_DIRECT_NTS
        && reg->pre_count[id] > 0) {
        for (int i = 0; i < reg->pre_count[id]; i++) {
            n00b_xform_entry_t  *entry = reg->pre_order[id][i];
            n00b_xform_control_t ctrl  = N00B_XFORM_CONTINUE;
            n00b_parse_tree_t *replaced = entry->pre_fn(
                ctx, result ? result : node, &ctrl);

            if (replaced) {
                result = replaced;
                ctx->nodes_replaced++;
            }

            if (ctrl == N00B_XFORM_SKIP_CHILDREN) {
                *control = N00B_XFORM_SKIP_CHILDREN;
            }
        }
    }

    // Wildcard pre transforms.
    for (int i = 0; i < reg->wildcard_pre_count; i++) {
        n00b_xform_entry_t  *entry = reg->wildcard_pre[i];
        n00b_xform_control_t ctrl  = N00B_XFORM_CONTINUE;
        n00b_parse_tree_t *replaced = entry->pre_fn(
            ctx, result ? result : node, &ctrl);

        if (replaced) {
            result = replaced;
            ctx->nodes_replaced++;
        }

        if (ctrl == N00B_XFORM_SKIP_CHILDREN) {
            *control = N00B_XFORM_SKIP_CHILDREN;
        }
    }

    return result;
}

static n00b_parse_tree_t *
apply_post(n00b_xform_registry_t *reg, n00b_xform_ctx_t *ctx,
           n00b_parse_tree_t *node)
{
    n00b_parse_tree_t *result = NULL;

    int64_t id = n00b_pt_nt_id(node);

    // Type-specific post transforms.
    if (id >= 0 && id < N00B_XFORM_MAX_DIRECT_NTS
        && reg->post_count[id] > 0) {
        for (int i = 0; i < reg->post_count[id]; i++) {
            n00b_xform_entry_t *entry = reg->post_order[id][i];
            n00b_parse_tree_t *replaced = entry->post_fn(
                ctx, result ? result : node);

            if (replaced) {
                result = replaced;
                ctx->nodes_replaced++;
            }
        }
    }

    // Wildcard post transforms.
    for (int i = 0; i < reg->wildcard_post_count; i++) {
        n00b_xform_entry_t *entry = reg->wildcard_post[i];
        n00b_parse_tree_t *replaced = entry->post_fn(
            ctx, result ? result : node);

        if (replaced) {
            result = replaced;
            ctx->nodes_replaced++;
        }
    }

    return result;
}

// ============================================================================
// Tree walker (iterative stack-based)
// ============================================================================

typedef struct {
    n00b_parse_tree_t *node;
    n00b_parse_tree_t *current;  // After pre-transform.
    int                child_idx;
    bool               skip_children;
} walk_item_t;

#define WALK_STACK_INITIAL 256

static n00b_parse_tree_t *
walk_tree(n00b_xform_registry_t *reg, n00b_xform_ctx_t *ctx,
          n00b_parse_tree_t *root)
{
    if (!root) {
        return NULL;
    }

    int          stack_cap = WALK_STACK_INITIAL;
    int          stack_top = 0;
    walk_item_t *stack     = n00b_alloc_array(walk_item_t, stack_cap);

    if (!stack) {
        return root;
    }

    stack[stack_top++] = (walk_item_t){
        .node          = root,
        .current       = root,
        .child_idx     = -1,
        .skip_children = false,
    };

    n00b_parse_tree_t *final_result = root;

    while (stack_top > 0) {
        walk_item_t *item = &stack[stack_top - 1];

        // Phase 1: Pre-order.
        if (item->child_idx == -1) {
            n00b_parse_tree_t *node = item->node;
            ctx->nodes_visited++;
            ctx->depth++;

            n00b_xform_control_t control    = N00B_XFORM_CONTINUE;
            n00b_parse_tree_t   *pre_result = apply_pre(reg, ctx, node,
                                                          &control);

            item->current       = pre_result ? pre_result : node;
            item->skip_children = (control == N00B_XFORM_SKIP_CHILDREN);
            item->child_idx     = 0;
        }

        n00b_parse_tree_t *current = item->current;

        // Phase 2: Process children.
        size_t nch = n00b_pt_num_children(current);

        if (!item->skip_children && (size_t)item->child_idx < nch) {
            n00b_parse_tree_t *child = n00b_tree_child(
                current, item->child_idx);

            if (child) {
                // Grow stack if needed.
                if (stack_top >= stack_cap) {
                    int new_cap = stack_cap * 2;
                    walk_item_t *new_stack = n00b_alloc_array(
                        walk_item_t, new_cap);

                    if (!new_stack) {
                        n00b_free(stack);
                        return root;
                    }

                    memcpy(new_stack, stack,
                           (size_t)stack_top * sizeof(walk_item_t));
                    n00b_free(stack);
                    stack     = new_stack;
                    stack_cap = new_cap;
                    item      = &stack[stack_top - 1];
                }

                stack[stack_top++] = (walk_item_t){
                    .node          = child,
                    .current       = child,
                    .child_idx     = -1,
                    .skip_children = false,
                };
                item->child_idx++;
                continue;
            }
            else {
                item->child_idx++;
                continue;
            }
        }

        // Phase 3: Post-order.
        if (item->skip_children) {
            item->child_idx = (int)nch;
        }

        if ((size_t)item->child_idx >= nch) {
            n00b_parse_tree_t *post_result = apply_post(reg, ctx, current);

            if (post_result) {
                current       = post_result;
                item->current = post_result;
            }

            ctx->depth--;

            n00b_parse_tree_t *result = item->current;
            n00b_parse_tree_t *orig   = item->node;
            stack_top--;

            // Update parent's child pointer if replaced.
            if (stack_top > 0 && result != orig) {
                walk_item_t *parent_item = &stack[stack_top - 1];
                int          child_ix    = parent_item->child_idx - 1;

                if (child_ix >= 0
                    && (size_t)child_ix
                           < n00b_pt_num_children(parent_item->current)) {
                    (void)n00b_tree_set_child(parent_item->current,
                                              (size_t)child_ix, result);
                }
            }

            if (stack_top == 0) {
                final_result = result;
            }
        }
    }

    n00b_free(stack);
    return final_result;
}

// ============================================================================
// Public API: apply
// ============================================================================

n00b_parse_tree_t *
n00b_xform_apply(n00b_xform_registry_t *reg, n00b_xform_ctx_t *ctx)
{
    assert(reg && ctx);

    ctx->nodes_visited  = 0;
    ctx->nodes_replaced = 0;
    ctx->depth          = 0;

    if (!ctx->root) {
        return NULL;
    }

    n00b_parse_tree_t *result = walk_tree(reg, ctx, ctx->root);

    if (result != ctx->root) {
        ctx->root = result;
    }

    return result;
}

n00b_parse_tree_t *
n00b_xform_apply_multi(n00b_xform_registry_t *reg,
                         n00b_xform_ctx_t      *ctx,
                         int                    max_passes)
{
    assert(reg && ctx);

    if (max_passes <= 0) {
        max_passes = 100;
    }

    ctx->pass = 0;

    while (ctx->pass < max_passes) {
        n00b_parse_tree_t *result = n00b_xform_apply(reg, ctx);

        if (ctx->nodes_replaced == 0) {
            break;
        }

        ctx->pass++;
        ctx->root = result;
    }

    return ctx->root;
}

// ============================================================================
// Template-based subtree construction
// ============================================================================

// Error codes for n00b_xform_parse_template.
#define N00B_XFORM_ERR_NO_TOKENIZER 1
#define N00B_XFORM_ERR_UNKNOWN_NT   2
#define N00B_XFORM_ERR_PARSE_FAILED 3

n00b_result_t(n00b_parse_tree_t *)
n00b_xform_parse_template(n00b_grammar_t *grammar,
                           const char     *nt_name,
                           const char     *source) _kargs {
    n00b_scan_cb_t tokenize;
}
{
    assert(grammar && nt_name && source);

    // Resolve the tokenizer: explicit karg > grammar's stored cb > registry > default.
    n00b_scan_cb_t cb = tokenize ? tokenize : grammar->tokenize_cb;

    if (!cb && grammar->tokenizer_name) {
        bool found = false;
        cb = n00b_tokenizer_lookup(grammar->tokenizer_name->data, &found);
    }

    if (!cb) {
        bool found = false;
        cb = n00b_tokenizer_lookup("text", &found);
    }

    if (cb) {
        grammar->tokenize_cb = cb;
    }

    if (!cb) {
        return n00b_result_err(n00b_parse_tree_t *, N00B_XFORM_ERR_NO_TOKENIZER);
    }

    // Resolve the NT name to an id.
    n00b_string_t *nt_str = n00b_string_from_cstr(nt_name);
    n00b_nonterm_t *nt   = n00b_nonterm(grammar, nt_str);

    if (!nt) {
        return n00b_result_err(n00b_parse_tree_t *, N00B_XFORM_ERR_UNKNOWN_NT);
    }

    int64_t nt_id = n00b_nonterm_id(nt);

    // Save the grammar's default start and override.
    int32_t saved_start    = grammar->default_start;
    grammar->default_start = (int32_t)nt_id;

    // Tokenize.
    n00b_buffer_t       *buf     = n00b_buffer_from_cstr(source);
    n00b_scanner_t      *scanner = n00b_scanner_new(buf, cb, grammar);
    n00b_token_stream_t *ts      = n00b_token_stream_new(scanner);

    // Parse (backend selection comes from the grammar's instantiation mode).
    n00b_parse_result_t *result = n00b_grammar_parse(grammar, ts);

    // Restore the grammar's original start.
    grammar->default_start = saved_start;

    n00b_result_t(n00b_parse_tree_t *) ret;

    if (n00b_parse_result_ok(result)) {
        ret = n00b_result_ok(n00b_parse_tree_t *,
                             n00b_xform_clone(n00b_parse_result_tree(result)));
    }
    else {
        ret = n00b_result_err(n00b_parse_tree_t *, N00B_XFORM_ERR_PARSE_FAILED);
    }

    n00b_parse_result_free(result);
    n00b_token_stream_free(ts);
    n00b_scanner_free(scanner);

    return ret;
}
