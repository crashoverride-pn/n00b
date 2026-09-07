#include <stdio.h>
#include <assert.h>

#include "n00b.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "text/strings/string_ops.h"
#include "slay/symtab.h"
#include "slay/annot_walk.h"
#include "slay/grammar.h"
#include "slay/annotation.h"
#include "slay/parse_tree.h"
#include "slay/n00b_parse.h"
#include "internal/slay/grammar_internal.h"

// Helper: add an epsilon rule for an NT and return its rule index.
static int32_t
add_epsilon_rule(n00b_grammar_t *g, n00b_nonterm_t *nt)
{
    n00b_match_t       empty = {.kind = N00B_MATCH_EMPTY};
    n00b_parse_rule_t *rule  = n00b_add_rule_v(g, nt->id, 1, &empty);

    assert(rule != NULL);

    // Return the local rule index (position within the NT's rule_ids list).
    // The annotation walk expects local indices, matching what the Earley
    // parser stores in parse tree nodes.
    nt = n00b_get_nonterm(g, nt->id);

    return (int32_t)(n00b_list_len(nt->rule_ids) - 1);
}

// ============================================================================
// 1. Basic lifecycle
// ============================================================================

static void
test_symtab_new_free(void)
{
    n00b_symtab_t *st = n00b_symtab_new();
    assert(st != NULL);
    assert(st->ns_count == 0);
    n00b_symtab_free(st);
    printf("  [PASS] symtab_new_free\n");
}

// ============================================================================
// 2. Namespace creation
// ============================================================================

static void
test_namespace_create(void)
{
    n00b_symtab_t *st = n00b_symtab_new();

    // Default namespace.
    n00b_namespace_t *ns = n00b_symtab_ns(st, n00b_string_empty());
    assert(ns != NULL);
    assert(st->ns_count == 1);

    // Tag namespace.
    n00b_namespace_t *tag_ns = n00b_symtab_ns(st, r"tag");
    assert(tag_ns != NULL);
    assert(st->ns_count == 2);

    // Re-fetch default namespace — should return same pointer.
    n00b_namespace_t *ns2 = n00b_symtab_ns(st, n00b_string_empty());
    assert(ns2 == ns);
    assert(st->ns_count == 2);

    n00b_symtab_free(st);
    printf("  [PASS] namespace_create\n");
}

// ============================================================================
// 3. Add and lookup
// ============================================================================

static void
test_add_lookup(void)
{
    n00b_symtab_t *st = n00b_symtab_new();

    n00b_sym_entry_t *e = n00b_symtab_add(st,
                                            n00b_string_empty(),
                                            r"x",
                                            N00B_SYM_VARIABLE,
                                            NULL);
    assert(e != NULL);
    assert(e->kind == N00B_SYM_VARIABLE);
    assert(n00b_unicode_str_eq(e->name, r"x"));

    // Lookup should find it.
    n00b_sym_entry_t *found = n00b_symtab_lookup(st, n00b_string_empty(), r"x");
    assert(found == e);

    // Lookup of non-existent symbol.
    n00b_sym_entry_t *miss = n00b_symtab_lookup(st, n00b_string_empty(), r"y");
    assert(miss == NULL);

    n00b_symtab_free(st);
    printf("  [PASS] add_lookup\n");
}

// ============================================================================
// 4. Push/pop scope with shadowing
// ============================================================================

static void
test_scope_shadowing(void)
{
    n00b_symtab_t *st = n00b_symtab_new();

    // Add 'x' at file scope.
    n00b_sym_entry_t *outer = n00b_symtab_add(st,
                                                n00b_string_empty(),
                                                r"x",
                                                N00B_SYM_VARIABLE,
                                                NULL);
    assert(outer != NULL);

    // Push a new scope.
    n00b_symtab_push_scope(st, n00b_string_empty(), r"block1");
    assert(n00b_symtab_depth(st, n00b_string_empty()) == 1);

    // Add 'x' again — shadows the outer one.
    n00b_sym_entry_t *inner = n00b_symtab_add(st,
                                                n00b_string_empty(),
                                                r"x",
                                                N00B_SYM_VARIABLE,
                                                NULL);
    assert(inner != NULL);
    assert(inner != outer);
    assert(inner->shadowed == outer);

    // Lookup should find the inner one.
    n00b_sym_entry_t *found = n00b_symtab_lookup(st, n00b_string_empty(), r"x");
    assert(found == inner);

    // Pop scope — should restore outer.
    n00b_symtab_pop_scope(st, n00b_string_empty());
    assert(n00b_symtab_depth(st, n00b_string_empty()) == 0);

    found = n00b_symtab_lookup(st, n00b_string_empty(), r"x");
    assert(found == outer);

    n00b_symtab_free(st);
    printf("  [PASS] scope_shadowing\n");
}

// ============================================================================
// 5. Independent namespaces
// ============================================================================

static void
test_independent_namespaces(void)
{
    n00b_symtab_t *st = n00b_symtab_new();

    // Add 'foo' in default namespace.
    n00b_symtab_add(st, n00b_string_empty(), r"foo", N00B_SYM_VARIABLE, NULL);

    // Add 'foo' in tag namespace — independent.
    n00b_symtab_add(st, r"tag", r"foo", N00B_SYM_TAG, NULL);

    // Lookup in each namespace.
    n00b_sym_entry_t *var = n00b_symtab_lookup(st, n00b_string_empty(), r"foo");
    n00b_sym_entry_t *tag = n00b_symtab_lookup(st, r"tag", r"foo");
    assert(var != NULL);
    assert(tag != NULL);
    assert(var->kind == N00B_SYM_VARIABLE);
    assert(tag->kind == N00B_SYM_TAG);

    // Push scope on "tag" namespace only.
    n00b_symtab_push_scope(st, r"tag", r"inner");
    n00b_symtab_add(st, r"tag", r"foo", N00B_SYM_TAG, NULL);

    // Default namespace unaffected.
    n00b_sym_entry_t *still_var = n00b_symtab_lookup(st, n00b_string_empty(), r"foo");
    assert(still_var == var);

    // Tag namespace sees the inner one.
    n00b_sym_entry_t *inner_tag = n00b_symtab_lookup(st, r"tag", r"foo");
    assert(inner_tag != tag);
    assert(inner_tag->shadowed == tag);

    // Pop tag scope — restored.
    n00b_symtab_pop_scope(st, r"tag");
    n00b_sym_entry_t *restored = n00b_symtab_lookup(st, r"tag", r"foo");
    assert(restored == tag);

    n00b_symtab_free(st);
    printf("  [PASS] independent_namespaces\n");
}

// ============================================================================
// 6. Nested scopes
// ============================================================================

static void
test_nested_scopes(void)
{
    n00b_symtab_t *st = n00b_symtab_new();

    n00b_symtab_add(st, n00b_string_empty(), r"a", N00B_SYM_VARIABLE, NULL);

    // Depth 1.
    n00b_symtab_push_scope(st, n00b_string_empty(), r"d1");
    n00b_symtab_add(st, n00b_string_empty(), r"b", N00B_SYM_VARIABLE, NULL);
    n00b_symtab_add(st, n00b_string_empty(), r"a", N00B_SYM_VARIABLE, NULL);

    // Depth 2.
    n00b_symtab_push_scope(st, n00b_string_empty(), r"d2");
    n00b_symtab_add(st, n00b_string_empty(), r"c", N00B_SYM_VARIABLE, NULL);
    n00b_symtab_add(st, n00b_string_empty(), r"a", N00B_SYM_VARIABLE, NULL);

    assert(n00b_symtab_depth(st, n00b_string_empty()) == 2);

    // Innermost 'a'.
    n00b_sym_entry_t *a = n00b_symtab_lookup(st, n00b_string_empty(), r"a");
    assert(a != NULL);
    assert(a->scope_depth == 2);
    assert(a->shadowed != NULL);
    assert(a->shadowed->scope_depth == 1);
    assert(a->shadowed->shadowed != NULL);
    assert(a->shadowed->shadowed->scope_depth == 0);

    // Pop depth 2.
    n00b_symtab_pop_scope(st, n00b_string_empty());
    a = n00b_symtab_lookup(st, n00b_string_empty(), r"a");
    assert(a->scope_depth == 1);
    assert(n00b_symtab_lookup(st, n00b_string_empty(), r"c") == NULL);

    // Pop depth 1.
    n00b_symtab_pop_scope(st, n00b_string_empty());
    a = n00b_symtab_lookup(st, n00b_string_empty(), r"a");
    assert(a->scope_depth == 0);
    assert(n00b_symtab_lookup(st, n00b_string_empty(), r"b") == NULL);

    n00b_symtab_free(st);
    printf("  [PASS] nested_scopes\n");
}

// ============================================================================
// 7. Typedef detection
// ============================================================================

static void
test_typedef_detection(void)
{
    n00b_symtab_t *st = n00b_symtab_new();

    n00b_symtab_add(st, n00b_string_empty(), r"MyInt", N00B_SYM_TYPEDEF, NULL);
    n00b_symtab_add(st, n00b_string_empty(), r"x", N00B_SYM_VARIABLE, NULL);

    assert(n00b_symtab_is_typedef(st, r"MyInt") == true);
    assert(n00b_symtab_is_typedef(st, r"x") == false);
    assert(n00b_symtab_is_typedef(st, r"unknown") == false);

    n00b_symtab_free(st);
    printf("  [PASS] typedef_detection\n");
}

// ============================================================================
// 8. Annotation walk with a simple grammar
// ============================================================================

static void
test_annot_walk_scope(void)
{
    // Build a minimal grammar: "decl" declares at file scope,
    // "block" opens a scope. Verify that file-scope declarations
    // survive and that the scope depth returns to 0 after the walk.

    n00b_grammar_t *g = n00b_grammar_new();

    // Create all NTs first (list may reallocate, invalidating pointers).
    (void)n00b_nonterm(g, r"program");
    (void)n00b_nonterm(g, r"decl");
    (void)n00b_nonterm(g, r"block");

    // Re-fetch stable pointers and attach annotations.
    n00b_nonterm_t *prog = n00b_nonterm(g, r"program");
    n00b_nonterm_t *decl = n00b_nonterm(g, r"decl");
    n00b_nonterm_t *blk  = n00b_nonterm(g, r"block");

    // "decl" declares from child 0 (at whatever scope is current).
    n00b_nt_declares(decl, N00B_CHILD_IX(0), N00B_CHILD_NONE, n00b_string_empty());

    // "block" opens a scope.
    n00b_nt_scope_open(blk, n00b_string_empty(), N00B_CHILD_NONE);

    // Add epsilon rules and finalize so annotations land on rules.
    int32_t prog_ri = add_epsilon_rule(g, prog);
    int32_t decl_ri = add_epsilon_rule(g, decl);
    int32_t blk_ri  = add_epsilon_rule(g, blk);
    n00b_grammar_set_start(g, n00b_nonterm(g, r"program"));
    n00b_grammar_finalize(g);

    // Build tree: program -> [decl("x"), block]
    n00b_nt_node_t prog_pn = {.id = prog->id, .name = r"program", .rule_index = prog_ri};
    n00b_parse_tree_t *prog_tree
        = n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, prog_pn);

    // Decl node with token child "x".
    n00b_nt_node_t decl_pn = {.id = decl->id, .name = r"decl", .rule_index = decl_ri};
    n00b_parse_tree_t *decl_tree
        = n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, decl_pn);
    n00b_token_info_t tok = {0};
    tok.value = n00b_option_set(n00b_string_t *, r"x");
    tok.tid   = 1;  // Arbitrary non-sentinel ID (annotation walk uses value text).
    n00b_parse_tree_t *tok_tree
        = n00b_tree_leaf(n00b_nt_node_t, n00b_token_info_t *, &tok);
    (void)n00b_tree_add_child(decl_tree, tok_tree);

    // Empty block node.
    n00b_nt_node_t blk_pn = {.id = blk->id, .name = r"block", .rule_index = blk_ri};
    n00b_parse_tree_t *blk_tree
        = n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, blk_pn);

    (void)n00b_tree_add_child(prog_tree, decl_tree);
    (void)n00b_tree_add_child(prog_tree, blk_tree);

    // Walk the tree.
    n00b_symtab_t *st = n00b_annot_walk_tree(g, prog_tree);
    assert(st != NULL);

    // "x" was declared at file scope (outside the block), so it survives.
    n00b_sym_entry_t *e = n00b_symtab_lookup(st, n00b_string_empty(), r"x");
    assert(e != NULL);
    assert(e->kind == N00B_SYM_VARIABLE);

    // After the walk, the block scope was popped — depth back to 0.
    assert(n00b_symtab_depth(st, n00b_string_empty()) == 0);

    n00b_symtab_free(st);
    n00b_parse_tree_free(prog_tree);
    n00b_grammar_free(g);
    printf("  [PASS] annot_walk_scope\n");
}

// ============================================================================
// 9. Annotation walk with type_decl
// ============================================================================

static void
test_annot_walk_typedef(void)
{
    n00b_grammar_t *g = n00b_grammar_new();

    // Create all NTs first, then re-fetch to avoid stale pointers.
    (void)n00b_nonterm(g, r"program");
    (void)n00b_nonterm(g, r"type_decl");

    n00b_nonterm_t *prog = n00b_nonterm(g, r"program");
    n00b_nonterm_t *decl = n00b_nonterm(g, r"type_decl");

    // Mark type_decl as declaring a typedef via name child at index 0.
    n00b_nt_type_decl(decl, N00B_CHILD_IX(0));

    // Add epsilon rules and finalize so annotations land on rules.
    int32_t prog_ri = add_epsilon_rule(g, prog);
    int32_t decl_ri = add_epsilon_rule(g, decl);
    n00b_grammar_set_start(g, n00b_nonterm(g, r"program"));
    n00b_grammar_finalize(g);

    // Build tree: program -> type_decl -> "MyType" (token)
    n00b_nt_node_t prog_pn = {.id = prog->id, .name = r"program", .rule_index = prog_ri};
    n00b_parse_tree_t *prog_tree
        = n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, prog_pn);

    n00b_nt_node_t decl_pn = {.id = decl->id, .name = r"type_decl", .rule_index = decl_ri};
    n00b_parse_tree_t *decl_tree
        = n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, decl_pn);

    n00b_token_info_t tok = {0};
    tok.value = n00b_option_set(n00b_string_t *, r"MyType");
    tok.tid   = 1;  // Arbitrary non-sentinel ID (annotation walk uses value text).

    n00b_parse_tree_t *tok_tree
        = n00b_tree_leaf(n00b_nt_node_t, n00b_token_info_t *, &tok);

    (void)n00b_tree_add_child(decl_tree, tok_tree);
    (void)n00b_tree_add_child(prog_tree, decl_tree);

    // Walk.
    n00b_symtab_t *st = n00b_annot_walk_tree(g, prog_tree);
    assert(st != NULL);

    // MyType should be a typedef.
    assert(n00b_symtab_is_typedef(st, r"MyType") == true);

    n00b_symtab_free(st);
    n00b_parse_tree_free(prog_tree);
    n00b_grammar_free(g);
    printf("  [PASS] annot_walk_typedef\n");
}

// ============================================================================
// 10. Scope push/pop happen automatically on production entry/exit
// ============================================================================

static void
test_scope_auto_push_pop(void)
{
    // Verify that pushing scope on entering a production and popping
    // on leaving is done automatically by the walk — declarations
    // inside the scope are visible during the walk but cleaned up after.

    n00b_grammar_t *g = n00b_grammar_new();

    // Create all NTs first, then re-fetch to avoid stale pointers.
    (void)n00b_nonterm(g, r"program");
    (void)n00b_nonterm(g, r"func");
    (void)n00b_nonterm(g, r"body");

    n00b_nonterm_t *prog = n00b_nonterm(g, r"program");
    n00b_nonterm_t *func = n00b_nonterm(g, r"func");
    n00b_nonterm_t *body = n00b_nonterm(g, r"body");

    // "func" opens a scope.
    n00b_nt_scope_open(func, n00b_string_empty(), N00B_CHILD_NONE);

    // "body" declares a variable at its first child.
    n00b_nt_declares(body, N00B_CHILD_IX(0), N00B_CHILD_NONE, n00b_string_empty());

    // Add epsilon rules and finalize so annotations land on rules.
    int32_t prog_ri = add_epsilon_rule(g, prog);
    int32_t func_ri = add_epsilon_rule(g, func);
    int32_t body_ri = add_epsilon_rule(g, body);
    n00b_grammar_set_start(g, n00b_nonterm(g, r"program"));
    n00b_grammar_finalize(g);

    // Tree: program -> func -> body -> "local_var"
    n00b_nt_node_t prog_pn = {.id = prog->id, .name = r"program", .rule_index = prog_ri};
    n00b_parse_tree_t *prog_tree = n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, prog_pn);

    n00b_nt_node_t func_pn = {.id = func->id, .name = r"func", .rule_index = func_ri};
    n00b_parse_tree_t *func_tree = n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, func_pn);

    n00b_nt_node_t body_pn = {.id = body->id, .name = r"body", .rule_index = body_ri};
    n00b_parse_tree_t *body_tree = n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, body_pn);

    n00b_token_info_t tok = {0};
    tok.value = n00b_option_set(n00b_string_t *, r"local_var");
    tok.tid   = 1;  // Arbitrary non-sentinel ID (annotation walk uses value text).

    n00b_parse_tree_t *tok_tree = n00b_tree_leaf(n00b_nt_node_t, n00b_token_info_t *, &tok);

    (void)n00b_tree_add_child(body_tree, tok_tree);
    (void)n00b_tree_add_child(func_tree, body_tree);
    (void)n00b_tree_add_child(prog_tree, func_tree);

    n00b_symtab_t *st = n00b_annot_walk_tree(g, prog_tree);
    assert(st != NULL);

    // After the walk, the scope was popped, so the local_var should
    // NOT be visible at file scope. The pop removed it from the hash table.
    n00b_sym_entry_t *e = n00b_symtab_lookup(st, n00b_string_empty(), r"local_var");
    assert(e == NULL);

    // Depth should be 0.
    assert(n00b_symtab_depth(st, n00b_string_empty()) == 0);

    n00b_symtab_free(st);
    n00b_parse_tree_free(prog_tree);
    n00b_grammar_free(g);
    printf("  [PASS] scope_auto_push_pop\n");
}

// ============================================================================
// 11. Pop scope removes only the scope's symbols (not outer ones)
// ============================================================================

static void
test_pop_preserves_outer(void)
{
    n00b_grammar_t *g = n00b_grammar_new();

    // Create all NTs first, then re-fetch to avoid stale pointers.
    (void)n00b_nonterm(g, r"program");
    (void)n00b_nonterm(g, r"decl");
    (void)n00b_nonterm(g, r"block");
    (void)n00b_nonterm(g, r"inner_decl");

    n00b_nonterm_t *prog       = n00b_nonterm(g, r"program");
    n00b_nonterm_t *decl       = n00b_nonterm(g, r"decl");
    n00b_nonterm_t *blk        = n00b_nonterm(g, r"block");
    n00b_nonterm_t *inner_decl = n00b_nonterm(g, r"inner_decl");

    // "decl" declares at child 0 (outer, no scope).
    n00b_nt_declares(decl, N00B_CHILD_IX(0), N00B_CHILD_NONE, n00b_string_empty());

    // "block" opens a scope.
    n00b_nt_scope_open(blk, n00b_string_empty(), N00B_CHILD_NONE);

    // "inner_decl" declares at child 0 (inside scope).
    n00b_nt_declares(inner_decl, N00B_CHILD_IX(0), N00B_CHILD_NONE, n00b_string_empty());

    // Add epsilon rules and finalize so annotations land on rules.
    int32_t prog_ri = add_epsilon_rule(g, prog);
    int32_t decl_ri = add_epsilon_rule(g, decl);
    int32_t blk_ri  = add_epsilon_rule(g, blk);
    int32_t id_ri   = add_epsilon_rule(g, inner_decl);
    n00b_grammar_set_start(g, n00b_nonterm(g, r"program"));
    n00b_grammar_finalize(g);

    // Tree: program -> [decl("outer"), block -> inner_decl("inner")]
    n00b_nt_node_t prog_pn = {.id = prog->id, .name = r"program", .rule_index = prog_ri};
    n00b_parse_tree_t *prog_tree = n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, prog_pn);

    // Outer decl of "outer".
    n00b_nt_node_t decl_pn = {.id = decl->id, .name = r"decl", .rule_index = decl_ri};
    n00b_parse_tree_t *decl_tree = n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, decl_pn);
    n00b_token_info_t tok1 = {0};
    tok1.value = n00b_option_set(n00b_string_t *, r"outer");
    n00b_parse_tree_t *tok1_tree = n00b_tree_leaf(n00b_nt_node_t, n00b_token_info_t *, &tok1);
    (void)n00b_tree_add_child(decl_tree, tok1_tree);

    // Block with inner decl.
    n00b_nt_node_t blk_pn = {.id = blk->id, .name = r"block", .rule_index = blk_ri};
    n00b_parse_tree_t *blk_tree = n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, blk_pn);

    n00b_nt_node_t id_pn = {.id = inner_decl->id, .name = r"inner_decl", .rule_index = id_ri};
    n00b_parse_tree_t *id_tree = n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, id_pn);
    n00b_token_info_t tok2 = {0};
    tok2.value = n00b_option_set(n00b_string_t *, r"inner");
    n00b_parse_tree_t *tok2_tree = n00b_tree_leaf(n00b_nt_node_t, n00b_token_info_t *, &tok2);
    (void)n00b_tree_add_child(id_tree, tok2_tree);
    (void)n00b_tree_add_child(blk_tree, id_tree);

    (void)n00b_tree_add_child(prog_tree, decl_tree);
    (void)n00b_tree_add_child(prog_tree, blk_tree);

    n00b_symtab_t *st = n00b_annot_walk_tree(g, prog_tree);
    assert(st != NULL);

    // "outer" should survive (declared outside the block scope).
    n00b_sym_entry_t *out = n00b_symtab_lookup(st, n00b_string_empty(), r"outer");
    assert(out != NULL);
    assert(out->kind == N00B_SYM_VARIABLE);

    // "inner" should have been removed when the block scope was popped.
    n00b_sym_entry_t *in = n00b_symtab_lookup(st, n00b_string_empty(), r"inner");
    assert(in == NULL);

    n00b_symtab_free(st);
    n00b_parse_tree_free(prog_tree);
    n00b_grammar_free(g);
    printf("  [PASS] pop_preserves_outer\n");
}

// ============================================================================
// main
// ============================================================================

int
main(int argc, char **argv)
{
    n00b_runtime_t runtime;
    n00b_init(&runtime, argc, argv);

    printf("Running symtab tests...\n");

    // Symbol table unit tests.
    test_symtab_new_free();
    test_namespace_create();
    test_add_lookup();
    test_scope_shadowing();
    test_independent_namespaces();
    test_nested_scopes();
    test_typedef_detection();

    // Annotation walk tests.
    test_annot_walk_scope();
    test_annot_walk_typedef();
    test_scope_auto_push_pop();
    test_pop_preserves_outer();

    printf("All symtab tests passed.\n");
    n00b_shutdown();
    return 0;
}
