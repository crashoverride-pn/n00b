// grammar.c - Grammar definition, error rules, and finalization.
#include "slay/grammar.h"
#include "internal/slay/grammar_internal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Nullability computation
// ============================================================================

static bool
check_stack_for_nt(n00b_list_t(int) *stack, int64_t ruleset)
{
    for (size_t i = 0; i < stack->len; i++) {
        if (ruleset == (int64_t)stack->data[i]) {
            return true;
        }
    }

    return false;
}

static inline void
finalize_nullable(n00b_nonterm_t *nt, bool value)
{
    nt->nullable  = value;
    nt->finalized = true;

    assert(!(nt->nullable && nt->group_nt) && "Group item cannot be nullable");
}

static bool
is_nullable_rule(n00b_grammar_t *g, n00b_parse_rule_t *rule, n00b_list_t(int) *stack);

static bool
is_nullable_nt(n00b_grammar_t *g, int64_t nt_id, n00b_list_t(int) *stack)
{
    if (stack && check_stack_for_nt(stack, nt_id)) {
        return true;
    }
    else {
        n00b_list_push(*stack, (int)nt_id);
    }

    n00b_nonterm_t *nt = n00b_get_nonterm(g, nt_id);

    if (nt->finalized) {
        return nt->nullable;
    }

    if (nt->rule_ids.len == 0) {
        finalize_nullable(nt, true);
        return true;
    }

    bool found_any_rule = false;

    for (size_t i = 0; i < nt->rule_ids.len; i++) {
        n00b_parse_rule_t *cur_rule = n00b_get_rule(g, nt->rule_ids.data[i]);
        found_any_rule              = true;

        if (is_nullable_rule(g, cur_rule, stack)) {
            finalize_nullable(nt, true);
            (void)n00b_list_pop(int, *stack);
            return true;
        }
    }

    finalize_nullable(nt, !found_any_rule);
    (void)n00b_list_pop(int, *stack);

    return nt->nullable;
}

static bool
is_nullable_match(n00b_grammar_t *g, n00b_match_t *m, n00b_list_t(int) *stack)
{
    switch (m->kind) {
    case N00B_MATCH_EMPTY:
        return true;
    case N00B_MATCH_GROUP:
        return ((n00b_rule_group_t *)m->group)->min == 0;
    case N00B_MATCH_NT:
        return is_nullable_nt(g, m->nt_id, stack);
    default:
        return false;
    }
}

static bool
is_nullable_rule(n00b_grammar_t *g, n00b_parse_rule_t *rule, n00b_list_t(int) *stack)
{
    size_t n = rule->contents.len;

    for (size_t i = 0; i < n; i++) {
        n00b_match_t *item = &rule->contents.data[i];

        if (!is_nullable_match(g, item, stack)) {
            return false;
        }

        if (item->kind == N00B_MATCH_NT) {
            if (check_stack_for_nt(stack, item->nt_id)) {
                return false;
            }

            return is_nullable_nt(g, item->nt_id, stack);
        }
    }

    return false;
}

// ============================================================================
// Internal: rule management
// ============================================================================

static bool
matches_eq(n00b_match_t *a, n00b_match_t *b)
{
    if (a->kind != b->kind) {
        return false;
    }

    switch (a->kind) {
    case N00B_MATCH_EMPTY:
    case N00B_MATCH_ANY:
        return true;
    case N00B_MATCH_TERMINAL:
        return a->terminal_id == b->terminal_id;
    case N00B_MATCH_CLASS:
        return a->char_class == b->char_class;
    case N00B_MATCH_NT:
        return a->nt_id == b->nt_id;
    case N00B_MATCH_GROUP:
        return a->group == b->group;
    case N00B_MATCH_SET:
        return a->set_items == b->set_items;
    }

    return false;
}

static bool
rule_exists(n00b_grammar_t *g,
            n00b_nonterm_t *nt,
            n00b_list_t(n00b_match_t) *new_contents,
            int32_t *old_ix_out)
{
    size_t new_len = new_contents->len;

    for (size_t i = 0; i < nt->rule_ids.len; i++) {
        int32_t            rule_ix = nt->rule_ids.data[i];
        n00b_parse_rule_t *old     = n00b_get_rule(g, rule_ix);

        if (old->contents.len != new_len) {
            continue;
        }

        bool match = true;

        for (size_t j = 0; j < new_len; j++) {
            if (!matches_eq(&old->contents.data[j], &new_contents->data[j])) {
                match = false;
                break;
            }
        }

        if (match) {
            if (old_ix_out) {
                *old_ix_out = rule_ix;
            }

            return true;
        }
    }

    return false;
}

static int32_t
add_rule_internal(n00b_grammar_t *g,
                  n00b_nt_id_t    nt_id,
                  n00b_list_t(n00b_match_t) *items,
                  int      cost,
                  int32_t  penalty_link_ix,
                  int32_t *old_ix_out)
{
    assert(!g->finalized && "Cannot modify grammar after finalization");
    assert(items->len > 0 && "Empty productions not allowed");

    n00b_nonterm_t *nt = n00b_get_nonterm(g, nt_id);

    if (rule_exists(g, nt, items, old_ix_out)) {
        return -1;
    }

    n00b_parse_rule_t rule = {0};

    rule.nt_id        = nt_id;
    rule.contents     = *items;
    rule.cost         = cost;
    rule.penalty_rule = penalty_link_ix >= 0;
    rule.link_ix      = penalty_link_ix;

    n00b_list_push(g->rules, rule);

    int32_t ix = (int32_t)(g->rules.len - 1);
    n00b_list_push(nt->rule_ids, ix);

    return ix;
}

// ============================================================================
// Error rule generation
// ============================================================================

static void
create_one_error_rule_set(n00b_grammar_t *g, int32_t rule_ix)
{
    n00b_parse_rule_t *cur = n00b_get_rule(g, rule_ix);
    n00b_nt_id_t cur_nt_id = cur->nt_id;
    n00b_nonterm_t *cur_nt = n00b_get_nonterm(g, cur_nt_id);

    if (cur_nt->no_error_rule) {
        return;
    }

    size_t n      = cur->contents.len;
    int    tok_ct = 0;

    for (size_t i = 0; i < n; i++) {
        n00b_match_t *m = &cur->contents.data[i];

        if (m->kind == N00B_MATCH_NT || m->kind == N00B_MATCH_GROUP) {
            continue;
        }

        tok_ct++;

        // Re-resolve the nt pointer since a previous iteration's
        // n00b_nonterm() may have reallocated nt_list.
        n00b_nonterm_t *cur_nt = n00b_get_nonterm(g, cur_nt_id);

        char namebuf[256];
        snprintf(namebuf,
                 sizeof(namebuf),
                 "$term-%s-%d-%d",
                 (cur_nt->name && cur_nt->name->data) ? cur_nt->name->data : "?",
                 rule_ix,
                 tok_ct);
        n00b_string_t *name = n00b_string_from_cstr(namebuf);

        n00b_nonterm_t *nt_err    = n00b_nonterm(g, name);
        n00b_nt_id_t    nt_err_id = n00b_nonterm_id(nt_err);

        // Rule 1: match the terminal normally (cost 0)
        n00b_list_t(n00b_match_t) r1 = n00b_list_new_private(n00b_match_t);
        n00b_list_push(r1, *m);
        int32_t ok_ix = add_rule_internal(g, nt_err_id, &r1, 0, -1, NULL);

        // Rule 2: omit the terminal (penalty = token omission)
        n00b_list_t(n00b_match_t) r2 = n00b_list_new_private(n00b_match_t);
        n00b_match_t empty           = {.kind = N00B_MATCH_EMPTY};
        n00b_list_push(r2, empty);
        add_rule_internal(g, nt_err_id, &r2, 0, ok_ix, NULL);

        // Rule 3: junk prefix + terminal (bad prefix penalty)
        n00b_list_t(n00b_match_t) r3 = n00b_list_new_private(n00b_match_t);
        n00b_match_t any             = {.kind = N00B_MATCH_ANY};
        n00b_list_push(r3, any);
        n00b_list_push(r3, *m);
        add_rule_internal(g, nt_err_id, &r3, 0, ok_ix, NULL);

        // Re-fetch cur since the rule list may have been reallocated.
        cur                   = n00b_get_rule(g, rule_ix);
        cur->contents.data[i] = (n00b_match_t){.kind = N00B_MATCH_NT, .nt_id = nt_err_id};
    }
}

// ============================================================================
// Public API
// ============================================================================

n00b_grammar_t *
n00b_grammar_new() _kargs
{
    n00b_parse_mode_t parse_mode     = N00B_PARSE_MODE_DEFAULT;
    bool              error_recovery = true;
}
{
    n00b_grammar_t *g = n00b_alloc(n00b_grammar_t);

    // D-049: create the grammar's element lists via n00b_list_new(T) (not
    // zero-init + push) so each backing captures the link-time GC pointer-map
    // for its element type, making the grammar precisely scannable and thus
    // marshalable. n00b_nonterm_t / n00b_parse_rule_t have mixed pointer/scalar
    // fields; a conservative DEFAULT scan mis-reads a scalar word as a static
    // pointer and breaks marshaling.
    g->nt_list = n00b_list_new_private(n00b_nonterm_t);
    g->rules   = n00b_list_new_private(n00b_parse_rule_t);

    // Immutable backend selection + error-recovery policy (set once here).
    // Error-recovery rules are Earley-only; force them off for PWZ_ONLY
    // grammars regardless of the caller's error_recovery request, since PWZ
    // never consumes them (and building them bloats the grammar).
    g->parse_mode  = parse_mode;
    g->error_rules = (parse_mode == N00B_PARSE_MODE_PWZ_ONLY) ? false
                                                              : error_recovery;
    g->max_penalty           = N00B_DEFAULT_MAX_PENALTY;
    g->hide_penalty_rewrites = true;
    g->hide_groups           = true;

    g->nt_map = n00b_alloc(n00b_dict_t(n00b_string_t *, int64_t));
    n00b_dict_init(g->nt_map,
                   .hash = n00b_string_hash,
                   .skip_obj_hash = true);

    g->terminal_map = n00b_alloc(n00b_dict_t(n00b_string_t *, int64_t));
    n00b_dict_init(g->terminal_map,
                   .hash = n00b_string_hash,
                   .skip_obj_hash = true);

    g->literal_type_map = n00b_alloc(n00b_dict_t(n00b_string_t *, int64_t));
    n00b_dict_init(g->literal_type_map,
                   .hash = n00b_string_hash,
                   .skip_obj_hash = true);

    g->valid_tokens = n00b_alloc(n00b_dict_t(int64_t, bool));
    n00b_dict_init(g->valid_tokens,
                   .hash = n00b_hash_word,
                   .skip_obj_hash = true,
                   .scan_kind = N00B_GC_SCAN_KIND_NONE);

    g->terminal_by_id = n00b_alloc(n00b_dict_t(int64_t, n00b_string_t *));
    n00b_dict_init(g->terminal_by_id,
                   .hash = n00b_hash_word,
                   .skip_obj_hash = true);

    g->next_literal_type_id = 0;

    return g;
}

void
n00b_grammar_free(n00b_grammar_t *g)
{
    if (!g) {
        return;
    }

    for (size_t i = 0; i < g->rules.len; i++) {
        n00b_list_free(g->rules.data[i].contents);
    }

    n00b_list_free(g->rules);

    for (size_t i = 0; i < g->nt_list.len; i++) {
        n00b_nonterm_t *nt = &g->nt_list.data[i];

        n00b_list_free(nt->rule_ids);

        // Annotation structs and lists are GC-managed; no manual free needed.
    }

    n00b_list_free(g->nt_list);

    // The untyped dicts are GC-managed; explicit free for predictable cleanup.
    if (g->nt_map) {
        n00b_free(g->nt_map);
    }
    if (g->terminal_map) {
        n00b_free(g->terminal_map);
    }
    if (g->literal_type_map) {
        n00b_free(g->literal_type_map);
    }
    if (g->valid_tokens) {
        n00b_free(g->valid_tokens);
    }
    if (g->terminal_by_id) {
        n00b_free(g->terminal_by_id);
    }

    if (g->left_corner_sets) {
        n00b_free(g->left_corner_sets);
    }

    if (g->lr0_items) {
        n00b_free(g->lr0_items);
    }
    if (g->lr0_rule_item_base) {
        n00b_free(g->lr0_rule_item_base);
    }
    if (g->lr0_states) {
        n00b_free(g->lr0_states);
    }
    if (g->lr0_state_items) {
        n00b_free(g->lr0_state_items);
    }
    if (g->lr0_gotos) {
        n00b_free(g->lr0_gotos);
    }
    if (g->lr0_predict_state) {
        n00b_free(g->lr0_predict_state);
    }

    if (g->has_terminal_categories && g->terminal_categories) {
        n00b_free(g->terminal_categories);
    }

    if (g->tokenizer_name) {
        n00b_free(g->tokenizer_name->data);
    }
    n00b_free(g);
}

void
n00b_grammar_set_start_id(n00b_grammar_t *g, n00b_nt_id_t nt_id)
{
    g->default_start = nt_id;
}

void
n00b_grammar_set_max_penalty(n00b_grammar_t *g, uint32_t max)
{
    g->max_penalty = max;
}

void
n00b_grammar_set_disambiguator(n00b_grammar_t *g, n00b_tree_disambig_fn_t fn)
{
    g->disambiguator = fn;
}

int64_t
n00b_grammar_terminal_id(n00b_grammar_t *g, n00b_string_t *name)
{
    if (!g || !g->terminal_map || !name) {
        return 0;
    }

    bool    found = false;
    int64_t val   = n00b_dict_get(g->terminal_map, name, &found);

    return found ? val : 0;
}

n00b_nonterm_t *
n00b_nonterm(n00b_grammar_t *g, n00b_string_t *name)
{
    if (name) {
        bool           found    = false;
        int64_t        val      = n00b_dict_get(g->nt_map, name, &found);

        if (found) {
            return n00b_get_nonterm(g, val);
        }
    }

    n00b_nonterm_t nt = {0};

    nt.name = name;
    nt.id   = (int64_t)g->nt_list.len;
    // `rule_ids` stores int32_t scalars. If the zero-initialized list grows
    // on first push, the default scanner treats packed scalar pairs as
    // pointers, which makes finalized grammars unmarshalable.
    nt.rule_ids = n00b_list_new_private(int32_t,
                                        .scan_kind = N00B_GC_SCAN_KIND_NONE);

    n00b_list_push(g->nt_list, nt);

    if (name) {
        int64_t        id  = nt.id;
        n00b_dict_put(g->nt_map, name, id);
    }

    return n00b_get_nonterm(g, nt.id);
}

int64_t
n00b_nonterm_id(n00b_nonterm_t *nt)
{
    return nt->id;
}

int64_t
n00b_register_terminal(n00b_grammar_t *g, n00b_string_t *name)
{
    bool           found    = false;
    int64_t        val      = n00b_dict_get(g->terminal_map, name, &found);

    if (found) {
        return val;
    }

    // All fixed-text terminals get a hash-based ID (including single-char).
    int64_t id = n00b_token_id_from_text(name->data, name->u8_bytes);

    // Forward map: name -> id (key is hashed, stack-local is fine)
    n00b_dict_put(g->terminal_map, name, id);

    // Reverse map: id -> name.
    n00b_dict_put(g->terminal_by_id, id, name);

    return id;
}

int64_t
n00b_register_literal_type(n00b_grammar_t *g, n00b_string_t *name)
{
    bool           found    = false;
    int64_t        val      = n00b_dict_get(g->literal_type_map, name, &found);

    if (found) {
        return val;
    }

    int64_t id = g->next_literal_type_id++;

    n00b_dict_put(g->literal_type_map, name, id);

    // Also store reverse mapping for diagnostics/debug.
    n00b_dict_put(g->terminal_by_id, id, name);

    return id;
}

void
n00b_grammar_set_terminal_category(n00b_grammar_t *g,
                                   int64_t         terminal_id,
                                   n00b_string_t  *category)
{
    if (!g->has_terminal_categories) {
        g->terminal_categories = n00b_alloc(n00b_dict_t(int64_t, n00b_string_t *));
        n00b_dict_init(g->terminal_categories,
                       .hash = n00b_hash_word,
                       .skip_obj_hash = true);
        g->has_terminal_categories = true;
    }

    n00b_dict_put(g->terminal_categories, terminal_id, category);
}

void
n00b_set_action(n00b_nonterm_t *nt, n00b_walk_action_t action)
{
    nt->action = action;
}

void
n00b_nonterm_set_user_data(n00b_nonterm_t *nt, void *data)
{
    nt->user_data = data;
}

void *
n00b_nonterm_get_user_data(n00b_nonterm_t *nt)
{
    return nt->user_data;
}

void
n00b_nonterm_set_action(n00b_nonterm_t *nt, n00b_walk_action_t action)
{
    if (nt) {
        nt->action = action;
    }
}

void
n00b_grammar_set_default_action(n00b_grammar_t *g, n00b_walk_action_t action)
{
    if (g) {
        g->default_action = action;
    }
}

// ============================================================================
// Group match
// ============================================================================

static int32_t group_id_counter = 1;

n00b_match_t
n00b_group_match_v(n00b_grammar_t *g, int min, int max, int n, n00b_match_t *items)
{
    n00b_rule_group_t *group = n00b_alloc(n00b_rule_group_t);

    group->gid = group_id_counter++;
    group->min = min;
    group->max = max;

    char namebuf[64];
    snprintf(namebuf, sizeof(namebuf), "$$group_%d", group->gid);
    n00b_string_t *name = n00b_string_from_cstr(namebuf);

    n00b_nonterm_t *nt = n00b_nonterm(g, name);
    n00b_nt_id_t    nt_id = n00b_nonterm_id(nt);

    nt->group_nt = true;

    n00b_list_t(n00b_match_t) match_items = n00b_list_new_private(n00b_match_t);

    for (int i = 0; i < n; i++) {
        n00b_list_push(match_items, items[i]);
    }

    // Do NOT use `nt` after this — add_rule_internal can grow nt_list.
    add_rule_internal(g, nt_id, &match_items, 0, -1, NULL);

    group->contents_id = nt_id;

    return (n00b_match_t){.kind = N00B_MATCH_GROUP, .group = group};
}

// ============================================================================
// Rule building
// ============================================================================

n00b_parse_rule_t *
n00b_add_rule_v(n00b_grammar_t *g, n00b_nt_id_t nt_id, int n, n00b_match_t *items)
{
    n00b_list_t(n00b_match_t) match_items = n00b_list_new_private(n00b_match_t);

    for (int i = 0; i < n; i++) {
        n00b_list_push(match_items, items[i]);
    }

    int32_t old_ix = -1;
    int32_t ix     = add_rule_internal(g, nt_id, &match_items, 0, -1, &old_ix);

    return n00b_get_rule(g, ix >= 0 ? ix : old_ix);
}

n00b_parse_rule_t *
n00b_add_rule_with_cost_v(n00b_grammar_t *g,
                          n00b_nt_id_t    nt_id,
                          int             cost,
                          int             n,
                          n00b_match_t   *items)
{
    n00b_list_t(n00b_match_t) match_items = n00b_list_new_private(n00b_match_t);

    for (int i = 0; i < n; i++) {
        n00b_list_push(match_items, items[i]);
    }

    int32_t old_ix = -1;
    int32_t ix     = add_rule_internal(g, nt_id, &match_items, cost, -1, &old_ix);

    return n00b_get_rule(g, ix >= 0 ? ix : old_ix);
}

// ============================================================================
// FIRST set computation (iterative fixed-point)
// ============================================================================

static inline void
merge_first_set(n00b_dict_t(int64_t, bool) *dst, n00b_dict_t(int64_t, bool) *src)
{
    if (!src || src->length == 0) {
        return;
    }

    n00b_dict_foreach(src, k, v, {
        n00b_dict_put(dst, k, v);
    });
}

// Check if a match can derive the empty string, using the first_nullable
// array instead of nt->nullable (which has a known bug for non-NT-ending rules).
static inline bool
match_is_first_nullable(n00b_grammar_t *g, n00b_match_t *m, bool *first_nullable)
{
    (void)g;
    switch (m->kind) {
    case N00B_MATCH_EMPTY:
        return true;
    case N00B_MATCH_GROUP:
        return ((n00b_rule_group_t *)m->group)->min == 0;
    case N00B_MATCH_NT:
        return first_nullable[m->nt_id];
    default:
        return false;
    }
}

// Check if a rule can derive the empty string.
static bool
rule_is_first_nullable(n00b_grammar_t *g, n00b_parse_rule_t *rule, bool *fn)
{
    size_t n = rule->contents.len;

    for (size_t i = 0; i < n; i++) {
        if (!match_is_first_nullable(g, &rule->contents.data[i], fn)) {
            return false;
        }
    }

    return n > 0;
}

// Compute the FIRST set for a single rule, given current NT FIRST sets.
// Returns true if the rule's FIRST set changed.
static bool
update_rule_first(n00b_grammar_t *g, n00b_parse_rule_t *rule, bool *first_nullable)
{
    if (!rule->first_set) {
        rule->first_set = n00b_alloc(n00b_dict_t(int64_t, bool));
        n00b_dict_init(rule->first_set,
                       .hash = n00b_hash_word,
                       .skip_obj_hash = true,
                       .scan_kind = N00B_GC_SCAN_KIND_NONE);
    }

    n00b_isize_t old_len     = rule->first_set->length;
    bool         old_has_any = rule->first_has_any;

    size_t n = rule->contents.len;
    bool   val = true;

    for (size_t i = 0; i < n; i++) {
        n00b_match_t *m = &rule->contents.data[i];

        switch (m->kind) {
        case N00B_MATCH_TERMINAL:
            n00b_dict_put(rule->first_set, m->terminal_id, val);
            goto done;
        case N00B_MATCH_ANY:
        case N00B_MATCH_CLASS:
        case N00B_MATCH_SET:
            rule->first_has_any = true;
            goto done;
        case N00B_MATCH_EMPTY:
            break;
        case N00B_MATCH_GROUP: {
            n00b_rule_group_t *grp = (n00b_rule_group_t *)m->group;
            n00b_nonterm_t    *gnt = n00b_get_nonterm(g, grp->contents_id);

            if (gnt) {
                if (gnt->first_set) {
                    merge_first_set(rule->first_set, gnt->first_set);
                }

                if (gnt->first_has_any) {
                    rule->first_has_any = true;
                }
            }

            if (grp->min > 0) {
                goto done;
            }

            break;
        }
        case N00B_MATCH_NT: {
            n00b_nonterm_t *nt = n00b_get_nonterm(g, m->nt_id);

            if (nt) {
                if (nt->first_set) {
                    merge_first_set(rule->first_set, nt->first_set);
                }

                if (nt->first_has_any) {
                    rule->first_has_any = true;
                }

                if (!first_nullable[m->nt_id]) {
                    goto done;
                }
            }
            else {
                rule->first_has_any = true;
                goto done;
            }

            break;
        }
        }
    }

done:
    return rule->first_set->length != old_len || rule->first_has_any != old_has_any;
}

static void
compute_all_first_sets(n00b_grammar_t *g)
{
    size_t n_nts   = g->nt_list.len;
    size_t n_rules = g->rules.len;

    // Compute correct nullability for FIRST set purposes.
    // The parser's nt->nullable has a known limitation for rules ending
    // with non-NT nullable items (EMPTY, groups with min==0).  We compute
    // a separate array here via iterative fixed point.
    bool *first_nullable = n00b_alloc_array(bool, n_nts);

    bool fn_changed = true;

    while (fn_changed) {
        fn_changed = false;

        for (size_t i = 0; i < n_nts; i++) {
            if (first_nullable[i]) {
                continue;
            }

            n00b_nonterm_t *nt = n00b_get_nonterm(g, (int64_t)i);

            for (size_t j = 0; j < nt->rule_ids.len; j++) {
                n00b_parse_rule_t *rule = n00b_get_rule(g, nt->rule_ids.data[j]);

                if (rule_is_first_nullable(g, rule, first_nullable)) {
                    first_nullable[i] = true;
                    fn_changed        = true;
                    break;
                }
            }
        }
    }

    // Initialize all FIRST sets.
    for (size_t i = 0; i < n_nts; i++) {
        n00b_nonterm_t *nt = n00b_get_nonterm(g, (int64_t)i);

        nt->first_set = n00b_alloc(n00b_dict_t(int64_t, bool));
        n00b_dict_init(nt->first_set,
                       .hash = n00b_hash_word,
                       .skip_obj_hash = true,
                       .scan_kind = N00B_GC_SCAN_KIND_NONE);
        nt->first_has_any = false;
    }

    for (size_t i = 0; i < n_rules; i++) {
        n00b_parse_rule_t *rule = n00b_get_rule(g, (int32_t)i);

        rule->first_set = n00b_alloc(n00b_dict_t(int64_t, bool));
        n00b_dict_init(rule->first_set,
                       .hash = n00b_hash_word,
                       .skip_obj_hash = true,
                       .scan_kind = N00B_GC_SCAN_KIND_NONE);
        rule->first_has_any = false;
    }

    // Iterate until fixed point.
    bool changed = true;

    while (changed) {
        changed = false;

        for (size_t i = 0; i < n_rules; i++) {
            n00b_parse_rule_t *rule = n00b_get_rule(g, (int32_t)i);

            if (update_rule_first(g, rule, first_nullable)) {
                changed = true;
            }
        }

        // Merge rule FIRST sets into their NTs.
        for (size_t i = 0; i < n_nts; i++) {
            n00b_nonterm_t *nt      = n00b_get_nonterm(g, (int64_t)i);
            n00b_isize_t    old_len = nt->first_set->length;
            bool            old_any = nt->first_has_any;

            for (size_t j = 0; j < nt->rule_ids.len; j++) {
                int32_t            rule_ix = nt->rule_ids.data[j];
                n00b_parse_rule_t *rule    = n00b_get_rule(g, rule_ix);

                merge_first_set(nt->first_set, rule->first_set);

                if (rule->first_has_any) {
                    nt->first_has_any = true;
                }
            }

            if (nt->first_set->length != old_len || nt->first_has_any != old_any) {
                changed = true;
            }
        }
    }

    // Nullable NTs must not be filtered by FIRST: if the NT derives empty,
    // any token is compatible (it matches whatever follows the NT).
    for (size_t i = 0; i < n_nts; i++) {
        if (first_nullable[i]) {
            n00b_get_nonterm(g, (int64_t)i)->first_has_any = true;
        }
    }

    n00b_free(first_nullable);
}

// ============================================================================
// Left-corner sets (flat bitset array in grammar)
// ============================================================================

static void
compute_left_corners(n00b_grammar_t *g)
{
    size_t n_nts = g->nt_list.len;

    if (n_nts == 0) {
        return;
    }

    int32_t words = (int32_t)((n_nts + 63) / 64);

    g->lc_words_per_nt  = words;
    g->left_corner_sets = n00b_alloc_array_with_opts(
        uint64_t,
        n_nts * (size_t)words,
        &(n00b_alloc_opts_t){.scan_kind = N00B_GC_SCAN_KIND_NONE});

    // Each NT includes itself.
    for (size_t i = 0; i < n_nts; i++) {
        uint64_t *set = g->left_corner_sets + i * (size_t)words;

        set[i / 64] |= (uint64_t)1 << (i % 64);
    }

    // Compute direct left-corners.
    for (size_t i = 0; i < n_nts; i++) {
        n00b_nonterm_t *nt  = n00b_get_nonterm(g, (int64_t)i);
        uint64_t       *set = g->left_corner_sets + i * (size_t)words;

        for (size_t j = 0; j < nt->rule_ids.len; j++) {
            int32_t            rule_ix = nt->rule_ids.data[j];
            n00b_parse_rule_t *rule    = n00b_get_rule(g, rule_ix);
            size_t             n_match = rule->contents.len;

            for (size_t k = 0; k < n_match; k++) {
                n00b_match_t *m = &rule->contents.data[k];

                if (m->kind == N00B_MATCH_NT) {
                    size_t child_id = (size_t)m->nt_id;

                    set[child_id / 64] |= (uint64_t)1 << (child_id % 64);

                    n00b_nonterm_t *child = n00b_get_nonterm(g, m->nt_id);

                    if (!child->nullable) {
                        break;
                    }
                }
                else if (m->kind == N00B_MATCH_GROUP) {
                    n00b_rule_group_t *grp      = (n00b_rule_group_t *)m->group;
                    size_t             child_id = (size_t)grp->contents_id;

                    set[child_id / 64] |= (uint64_t)1 << (child_id % 64);

                    if (grp->min > 0) {
                        n00b_nonterm_t *gnt = n00b_get_nonterm(g, grp->contents_id);

                        if (!gnt->nullable) {
                            break;
                        }
                    }
                }
                else if (m->kind == N00B_MATCH_EMPTY) {
                    continue;
                }
                else {
                    break;
                }
            }
        }
    }

    // Transitive closure.
    bool changed = true;

    while (changed) {
        changed = false;

        for (size_t i = 0; i < n_nts; i++) {
            uint64_t *set_i = g->left_corner_sets + i * (size_t)words;

            for (size_t j = 0; j < n_nts; j++) {
                if (!((set_i[j / 64] >> (j % 64)) & 1)) {
                    continue;
                }

                uint64_t *set_j = g->left_corner_sets + j * (size_t)words;

                for (int32_t w = 0; w < words; w++) {
                    uint64_t new_bits = set_j[w] & ~set_i[w];

                    if (new_bits) {
                        set_i[w] |= new_bits;
                        changed = true;
                    }
                }
            }
        }
    }
}

// ============================================================================
// LR(0) state table construction
// ============================================================================

// Encode a n00b_match_t as an int64_t symbol for GOTO keys.
// Terminal IDs are already unique (hash-based or sequential), so no
// offset is needed. We use a high bit to distinguish terminals from NTs.
//
// NT        -> nt_id (always >= 0 and small)
// TERMINAL  -> terminal_id with bit 62 set (avoids collision with small NTs)
// GROUP     -> -(1000+gid)
// ANY       -> INT64_MIN + 1
// EMPTY     -> INT64_MIN + 2
// CLASS     -> INT64_MIN + 100 + class_id
// SET       -> INT64_MIN + 3
//
// The INT64_MIN + N sentinels are chosen to never collide with hash-based
// terminal IDs (which have bit 63 set, making them negative but > INT64_MIN + 1000).
#define LR0_SYM_ANY    (INT64_MIN + 1)
#define LR0_SYM_EMPTY  (INT64_MIN + 2)
#define LR0_SYM_SET    (INT64_MIN + 3)

static int64_t
lr0_symbol_of_match(n00b_match_t *m)
{
    switch (m->kind) {
    case N00B_MATCH_NT:
        return m->nt_id;
    case N00B_MATCH_TERMINAL:
        // Set bit 62 to distinguish from NT ids when terminal_id >= 0.
        // Hash-based IDs (bit 63 set) already can't collide with NTs.
        if (m->terminal_id >= 0) {
            return m->terminal_id | (1LL << 62);
        }
        return m->terminal_id;
    case N00B_MATCH_GROUP: {
        n00b_rule_group_t *grp = (n00b_rule_group_t *)m->group;
        return -(1000LL + grp->gid);
    }
    case N00B_MATCH_ANY:
        return LR0_SYM_ANY;
    case N00B_MATCH_EMPTY:
        return LR0_SYM_EMPTY;
    case N00B_MATCH_CLASS:
        return INT64_MIN + 100LL + (int64_t)m->char_class;
    case N00B_MATCH_SET:
        return LR0_SYM_SET;
    }

    return INT64_MIN;
}

// Build lr0_items[] and lr0_rule_item_base[].
// For each rule, items at dot 0..len.
static void
compute_lr0_items(n00b_grammar_t *g)
{
    size_t n_rules = g->rules.len;

    g->lr0_rule_item_base = n00b_alloc_array(int32_t, n_rules);

    // Count total items first.
    int32_t total = 0;

    for (size_t i = 0; i < n_rules; i++) {
        n00b_parse_rule_t *r   = n00b_get_rule(g, (int32_t)i);
        int32_t            len = (int32_t)r->contents.len;

        g->lr0_rule_item_base[i] = total;
        total += len + 1; // dot positions 0..len
    }

    g->lr0_items      = n00b_alloc_array(n00b_lr0_item_t, total);
    g->lr0_item_count = total;

    for (size_t i = 0; i < n_rules; i++) {
        n00b_parse_rule_t *r    = n00b_get_rule(g, (int32_t)i);
        int32_t            len  = (int32_t)r->contents.len;
        int32_t            base = g->lr0_rule_item_base[i];

        for (int32_t d = 0; d <= len; d++) {
            g->lr0_items[base + d] = (n00b_lr0_item_t){
                .rule_ix  = (int32_t)i,
                .dot      = (int16_t)d,
                .rule_len = (int16_t)len,
            };
        }
    }
}

// Compute the LR(0) closure of a set of items.
// seed_bits is a bitset over lr0_items; seed_list/seed_len are the explicit
// list of item_ids in the seed. On return, seed_bits and seed_list/seed_len
// are the closed set.
static void
lr0_closure(n00b_grammar_t *g, uint64_t *seed_bits, int32_t *seed_list, int32_t *seed_len)
{
    int32_t words = (g->lr0_item_count + 63) / 64;
    (void)words;

    // Fixed-point: process items in seed_list; if dot is before NT or GROUP,
    // add that NT's rules at dot=0.
    for (int32_t idx = 0; idx < *seed_len; idx++) {
        int32_t          item_id = seed_list[idx];
        n00b_lr0_item_t *item    = &g->lr0_items[item_id];

        if (item->dot >= item->rule_len) {
            continue;
        }

        n00b_parse_rule_t *rule = n00b_get_rule(g, item->rule_ix);
        n00b_match_t      *m    = &rule->contents.data[item->dot];

        int64_t predict_nt_id = -1;

        if (m->kind == N00B_MATCH_NT) {
            predict_nt_id = m->nt_id;
        }
        else if (m->kind == N00B_MATCH_GROUP) {
            n00b_rule_group_t *grp = (n00b_rule_group_t *)m->group;
            predict_nt_id          = grp->contents_id;
        }

        if (predict_nt_id < 0) {
            continue;
        }

        n00b_nonterm_t *nt = n00b_get_nonterm(g, predict_nt_id);

        if (!nt) {
            continue;
        }

        for (size_t r = 0; r < nt->rule_ids.len; r++) {
            int32_t rix      = nt->rule_ids.data[r];
            int32_t new_item = g->lr0_rule_item_base[rix]; // dot=0

            size_t   w    = (size_t)new_item / 64;
            uint64_t mask = (uint64_t)1 << ((size_t)new_item % 64);

            if (!(seed_bits[w] & mask)) {
                seed_bits[w] |= mask;
                seed_list[(*seed_len)++] = new_item;
            }
        }
    }
}

// Hash an item set (sorted array of item_ids) for state deduplication.
static uint64_t
lr0_state_hash(int32_t *items, int32_t count)
{
    uint64_t h = 0x9e3779b97f4a7c15ULL ^ (uint64_t)count;

    for (int32_t i = 0; i < count; i++) {
        h ^= ((uint64_t)items[i] + 0x9e3779b97f4a7c15ULL);
        h = (h ^ (h >> 30)) * 0xbf58476d1ce4e5b9ULL;
        h = (h ^ (h >> 27)) * 0x94d049bb133111ebULL;
        h ^= h >> 31;
    }

    return h;
}

// Simple comparison for sorted item arrays.
static bool
lr0_items_eq(int32_t *a, int32_t a_len, int32_t *b, int32_t b_len)
{
    if (a_len != b_len) {
        return false;
    }

    return memcmp(a, b, (size_t)a_len * sizeof(int32_t)) == 0;
}

// qsort comparator for int32_t.
static int
cmp_int32(const void *a, const void *b)
{
    int32_t x = *(const int32_t *)a;
    int32_t y = *(const int32_t *)b;

    return (x > y) - (x < y);
}

// Builder context for LR(0) state construction.
typedef struct {
    n00b_grammar_t  *g;
    int32_t         *state_starts;
    int32_t         *state_counts;
    int32_t         *state_items;
    int32_t          state_items_total;
    int32_t          state_items_cap;
    int32_t         *goto_starts;
    int32_t         *goto_counts;
    n00b_lr0_goto_t *gotos;
    int32_t          gotos_cap;
    int32_t          gotos_count;
    int32_t          states_cap;
    int32_t          states_count;
    int64_t         *dedup_hash;
    int32_t         *dedup_sid;
    int32_t          dedup_cap;
} lr0_builder_t;

// Find or create a state from a closed, sorted item set. Returns state_id.
static int32_t
lr0_find_or_create(lr0_builder_t *b, int32_t *items_buf, int32_t count)
{
    uint64_t h    = lr0_state_hash(items_buf, count);
    int32_t  mask = b->dedup_cap - 1;
    int32_t  idx  = (int32_t)(h & (uint64_t)mask);

    while (b->dedup_hash[idx]) {
        if ((uint64_t)b->dedup_hash[idx] == h) {
            int32_t sid   = b->dedup_sid[idx];
            int32_t s_off = b->state_starts[sid];
            int32_t s_cnt = b->state_counts[sid];

            if (lr0_items_eq(items_buf, count, &b->state_items[s_off], s_cnt)) {
                return sid;
            }
        }

        idx = (idx + 1) & mask;
    }

    // New state.
    int32_t sid = b->states_count++;

    if (sid >= b->states_cap) {
        int32_t old_cap = b->states_cap;
        b->states_cap *= 2;

        int32_t *new_state_starts = n00b_alloc_array(int32_t, b->states_cap);
        memcpy(new_state_starts, b->state_starts, (size_t)old_cap * sizeof(int32_t));
        n00b_free(b->state_starts);
        b->state_starts = new_state_starts;

        int32_t *new_state_counts = n00b_alloc_array(int32_t, b->states_cap);
        memcpy(new_state_counts, b->state_counts, (size_t)old_cap * sizeof(int32_t));
        n00b_free(b->state_counts);
        b->state_counts = new_state_counts;

        int32_t *new_goto_starts = n00b_alloc_array(int32_t, b->states_cap);
        memcpy(new_goto_starts, b->goto_starts, (size_t)old_cap * sizeof(int32_t));
        n00b_free(b->goto_starts);
        b->goto_starts = new_goto_starts;

        int32_t *new_goto_counts = n00b_alloc_array(int32_t, b->states_cap);
        memcpy(new_goto_counts, b->goto_counts, (size_t)old_cap * sizeof(int32_t));
        n00b_free(b->goto_counts);
        b->goto_counts = new_goto_counts;
    }

    while (b->state_items_total + count > b->state_items_cap) {
        int32_t  old_si_cap = b->state_items_cap;
        b->state_items_cap *= 2;

        int32_t *new_si = n00b_alloc_array(int32_t, b->state_items_cap);
        memcpy(new_si, b->state_items, (size_t)old_si_cap * sizeof(int32_t));
        n00b_free(b->state_items);
        b->state_items = new_si;
    }

    b->state_starts[sid] = b->state_items_total;
    b->state_counts[sid] = count;
    memcpy(&b->state_items[b->state_items_total],
           items_buf,
           (size_t)count * sizeof(int32_t));
    b->state_items_total += count;

    b->goto_starts[sid] = 0;
    b->goto_counts[sid] = 0;

    // Insert into dedup table, growing if needed.
    if (b->states_count * 4 >= b->dedup_cap * 3) {
        int32_t  old_dcap  = b->dedup_cap;
        int64_t *old_dhash = b->dedup_hash;
        int32_t *old_dsid  = b->dedup_sid;

        b->dedup_cap *= 2;
        b->dedup_hash = n00b_alloc_array(int64_t, b->dedup_cap);
        b->dedup_sid  = n00b_alloc_array(int32_t, b->dedup_cap);

        int32_t dmask = b->dedup_cap - 1;

        for (int32_t i = 0; i < old_dcap; i++) {
            if (old_dhash[i]) {
                int32_t di = (int32_t)((uint64_t)old_dhash[i] & (uint64_t)dmask);

                while (b->dedup_hash[di]) {
                    di = (di + 1) & dmask;
                }

                b->dedup_hash[di] = old_dhash[i];
                b->dedup_sid[di]  = old_dsid[i];
            }
        }

        n00b_free(old_dhash);
        n00b_free(old_dsid);

        idx = (int32_t)(h & (uint64_t)(b->dedup_cap - 1));

        while (b->dedup_hash[idx]) {
            idx = (idx + 1) & (b->dedup_cap - 1);
        }
    }

    b->dedup_hash[idx] = (int64_t)h;

    if (!b->dedup_hash[idx]) {
        b->dedup_hash[idx] = 1;
    }

    b->dedup_sid[idx] = sid;

    return sid;
}

// Build the LR(0) automaton.
static void
build_lr0_states(n00b_grammar_t *g)
{
    size_t n_rules = g->rules.len;
    size_t n_nts   = g->nt_list.len;

    if (n_rules == 0 || n_nts == 0) {
        return;
    }

    int32_t bitset_words = (g->lr0_item_count + 63) / 64;

    lr0_builder_t b = {
        .g                 = g,
        .states_cap        = 256,
        .states_count      = 0,
        .state_items_cap   = 4096,
        .state_items_total = 0,
        .gotos_cap         = 1024,
        .gotos_count       = 0,
        .dedup_cap         = 1024,
    };

    b.state_starts = n00b_alloc_array(int32_t, b.states_cap);
    b.state_counts = n00b_alloc_array(int32_t, b.states_cap);
    b.state_items  = n00b_alloc_array(int32_t, b.state_items_cap);
    b.goto_starts  = n00b_alloc_array(int32_t, b.states_cap);
    b.goto_counts  = n00b_alloc_array(int32_t, b.states_cap);
    b.gotos        = n00b_alloc_array(n00b_lr0_goto_t, b.gotos_cap);
    b.dedup_hash   = n00b_alloc_array(int64_t, b.dedup_cap);
    b.dedup_sid    = n00b_alloc_array(int32_t, b.dedup_cap);

    uint64_t *bits     = n00b_alloc_array(uint64_t, bitset_words);
    int32_t  *itemlist = n00b_alloc_array(int32_t, g->lr0_item_count);

    // Create initial state: closure of start NT's rules at dot=0.
    {
        n00b_nonterm_t *start = n00b_get_nonterm(g, g->default_start);

        memset(bits, 0, (size_t)bitset_words * sizeof(uint64_t));

        int32_t len = 0;

        for (size_t r = 0; r < start->rule_ids.len; r++) {
            int32_t rix  = start->rule_ids.data[r];
            int32_t item = g->lr0_rule_item_base[rix];

            size_t   w    = (size_t)item / 64;
            uint64_t mask = (uint64_t)1 << ((size_t)item % 64);

            if (!(bits[w] & mask)) {
                bits[w] |= mask;
                itemlist[len++] = item;
            }
        }

        lr0_closure(g, bits, itemlist, &len);
        qsort(itemlist, (size_t)len, sizeof(int32_t), cmp_int32);

        g->lr0_start_state = lr0_find_or_create(&b, itemlist, len);
    }

    int32_t sym_buf_sz = g->lr0_item_count > 256 ? g->lr0_item_count : 256;
    int64_t *sym_buf   = n00b_alloc_array(int64_t, sym_buf_sz);
    int32_t *kernel    = n00b_alloc_array(int32_t, g->lr0_item_count);

    for (int32_t si = 0; si < b.states_count; si++) {
        int32_t s_off = b.state_starts[si];
        int32_t s_cnt = b.state_counts[si];

        int32_t n_syms = 0;

        for (int32_t j = 0; j < s_cnt; j++) {
            n00b_lr0_item_t *it = &g->lr0_items[b.state_items[s_off + j]];

            if (it->dot >= it->rule_len) {
                continue;
            }

            n00b_parse_rule_t *rule = n00b_get_rule(g, it->rule_ix);
            n00b_match_t      *m    = &rule->contents.data[it->dot];
            int64_t            sym  = lr0_symbol_of_match(m);

            bool found = false;

            for (int32_t k = 0; k < n_syms; k++) {
                if (sym_buf[k] == sym) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                sym_buf[n_syms++] = sym;
            }
        }

        b.goto_starts[si] = b.gotos_count;

        for (int32_t s = 0; s < n_syms; s++) {
            int64_t sym = sym_buf[s];

            if (sym == LR0_SYM_EMPTY) {
                continue;
            }

            memset(bits, 0, (size_t)bitset_words * sizeof(uint64_t));
            int32_t klen = 0;

            for (int32_t j = 0; j < s_cnt; j++) {
                n00b_lr0_item_t *it = &g->lr0_items[b.state_items[s_off + j]];

                if (it->dot >= it->rule_len) {
                    continue;
                }

                n00b_parse_rule_t *rule = n00b_get_rule(g, it->rule_ix);
                n00b_match_t      *m    = &rule->contents.data[it->dot];

                if (lr0_symbol_of_match(m) != sym) {
                    continue;
                }

                int32_t next_item = b.state_items[s_off + j] + 1;

                size_t   w    = (size_t)next_item / 64;
                uint64_t mask = (uint64_t)1 << ((size_t)next_item % 64);

                if (!(bits[w] & mask)) {
                    bits[w] |= mask;
                    kernel[klen++] = next_item;
                }
            }

            if (klen == 0) {
                continue;
            }

            lr0_closure(g, bits, kernel, &klen);
            qsort(kernel, (size_t)klen, sizeof(int32_t), cmp_int32);

            int32_t dest = lr0_find_or_create(&b, kernel, klen);

            if (b.gotos_count >= b.gotos_cap) {
                int32_t          old_gcap = b.gotos_cap;
                b.gotos_cap *= 2;
                n00b_lr0_goto_t *new_gotos = n00b_alloc_array(n00b_lr0_goto_t, b.gotos_cap);
                memcpy(new_gotos, b.gotos, (size_t)old_gcap * sizeof(n00b_lr0_goto_t));
                n00b_free(b.gotos);
                b.gotos = new_gotos;
            }

            b.gotos[b.gotos_count++] = (n00b_lr0_goto_t){
                .symbol     = sym,
                .dest_state = dest,
            };
        }

        b.goto_counts[si] = b.gotos_count - b.goto_starts[si];
    }

    // Flatten into grammar struct.
    g->lr0_state_count = b.states_count;
    g->lr0_states      = n00b_alloc_array(n00b_lr0_state_t, b.states_count);

    for (int32_t i = 0; i < b.states_count; i++) {
        g->lr0_states[i] = (n00b_lr0_state_t){
            .items_start = b.state_starts[i],
            .items_count = b.state_counts[i],
            .gotos_start = b.goto_starts[i],
            .gotos_count = b.goto_counts[i],
        };
    }

    g->lr0_state_items_total = b.state_items_total;
    g->lr0_state_items       = b.state_items;

    g->lr0_goto_count = b.gotos_count;
    g->lr0_gotos      = b.gotos;

    n00b_free(b.state_starts);
    n00b_free(b.state_counts);
    n00b_free(b.goto_starts);
    n00b_free(b.goto_counts);
    n00b_free(b.dedup_hash);
    n00b_free(b.dedup_sid);
    n00b_free(bits);
    n00b_free(itemlist);
    n00b_free(sym_buf);
    n00b_free(kernel);
}

// For each NT, find the LR(0) state that corresponds to the closure of
// that NT's rules at dot=0.
static void
lr0_compute_predict_states(n00b_grammar_t *g)
{
    size_t n_nts = g->nt_list.len;

    g->lr0_predict_state = n00b_alloc_array(int32_t, n_nts);

    int32_t   bitset_words = (g->lr0_item_count + 63) / 64;
    uint64_t *bits         = n00b_alloc_array(uint64_t, bitset_words);
    int32_t  *itemlist     = n00b_alloc_array(int32_t, g->lr0_item_count);

    for (size_t i = 0; i < n_nts; i++) {
        n00b_nonterm_t *nt = n00b_get_nonterm(g, (int64_t)i);

        memset(bits, 0, (size_t)bitset_words * sizeof(uint64_t));
        int32_t len = 0;

        for (size_t r = 0; r < nt->rule_ids.len; r++) {
            int32_t rix  = nt->rule_ids.data[r];
            int32_t item = g->lr0_rule_item_base[rix];

            size_t   w    = (size_t)item / 64;
            uint64_t mask = (uint64_t)1 << ((size_t)item % 64);

            if (!(bits[w] & mask)) {
                bits[w] |= mask;
                itemlist[len++] = item;
            }
        }

        lr0_closure(g, bits, itemlist, &len);
        qsort(itemlist, (size_t)len, sizeof(int32_t), cmp_int32);

        // Find matching state by comparing sorted item lists.
        int32_t found = -1;

        for (int32_t s = 0; s < g->lr0_state_count; s++) {
            n00b_lr0_state_t *st = &g->lr0_states[s];

            if (lr0_items_eq(itemlist,
                             len,
                             &g->lr0_state_items[st->items_start],
                             st->items_count)) {
                found = s;
                break;
            }
        }

        g->lr0_predict_state[i] = found;
    }

    n00b_free(bits);
    n00b_free(itemlist);
}

// ============================================================================
// Finalization
// ============================================================================

void
n00b_grammar_finalize(n00b_grammar_t *g)
{
    if (g->finalized) {
        return;
    }

    // Flush pending NT annotations to all of the NT's rules.
    // Programmatic users call n00b_nt_annotate() which stages on the NT;
    // here we distribute the same annotation pointers to every rule.
    for (size_t ni = 0; ni < g->nt_list.len; ni++) {
        n00b_nonterm_t *nt = &g->nt_list.data[ni];

        if (!nt->pending_annotations.data
                || !n00b_list_len(nt->pending_annotations)) {
            continue;
        }

        size_t nrules  = nt->rule_ids.data ? n00b_list_len(nt->rule_ids) : 0;
        size_t nannots = n00b_list_len(nt->pending_annotations);

        for (size_t ri = 0; ri < nrules; ri++) {
            int32_t            rule_ix = n00b_list_get(nt->rule_ids, ri);
            n00b_parse_rule_t *rule    = n00b_get_rule(g, rule_ix);

            if (!rule) {
                continue;
            }

            if (!rule->annotations.data) {
                rule->annotations = n00b_list_new_private(n00b_annotation_t *);
            }

            for (size_t ai = 0; ai < nannots; ai++) {
                n00b_annotation_t *a = n00b_list_get(nt->pending_annotations, ai);
                n00b_list_push(rule->annotations, a);
            }
        }
    }

    size_t n = g->nt_list.len;

    for (size_t i = 0; i < n; i++) {
        n00b_list_t(int) stack = n00b_list_new_private(int);
        is_nullable_nt(g, (int64_t)i, &stack);
        n00b_list_free(stack);
    }

    if (g->error_rules) {
        n = g->rules.len;

        for (size_t i = 0; i < n; i++) {
            create_one_error_rule_set(g, (int32_t)i);
        }
    }

    // Build valid_tokens set from all rules' terminal match items.
    bool true_val = true;

    for (size_t ri = 0; ri < g->rules.len; ri++) {
        n00b_parse_rule_t *r = &g->rules.data[ri];

        for (size_t mi = 0; mi < r->contents.len; mi++) {
            n00b_match_t *m = &r->contents.data[mi];

            if (m->kind == N00B_MATCH_TERMINAL) {
                n00b_dict_put(g->valid_tokens, m->terminal_id, true_val);
            }
        }
    }

    // Also add all literal type IDs to valid_tokens.
    for (int64_t i = 0; i < g->next_literal_type_id; i++) {
        n00b_dict_put(g->valid_tokens, i, true_val);
    }

    /* First-sets and left-corners are computed HERE: PWZ uses them to
     * prune (pwz.c nt_first_matches consults nt->first_set; a null
     * first_set means "matches everything", i.e. no pruning, which makes
     * PWZ explore pathologically on complex grammars). The Earley-only
     * LR0 tables (lr0_items / lr0_states / predict_states) are NOT
     * computed here — they are derived lazily by
     * n00b_grammar_compute_earley_analysis() the first time Earley runs
     * (n00b_earley_new), so PWZ-only consumers (naudit, the eval JIT,
     * baked grammars) skip that Earley-specific cost.
     *
     * (Historical note: a `N00B_SLAY_SKIP_FINALIZE_ANALYSIS` env var once
     * gated all of this here via libc `getenv()`, which faulted after any
     * `n00b_putenv()` rebinding of `environ`. The env var and the later
     * `skip_analysis` kwarg are gone; the Earley-only part now lives
     * behind the Earley entry point.) */
    compute_all_first_sets(g);
    compute_left_corners(g);

    // Check if the grammar has group NTs (BSR reconstruction doesn't
    // handle multi-match groups yet, so BSR emission is skipped).
    n = g->nt_list.len;

    for (size_t i = 0; i < n; i++) {
        if (g->nt_list.data[i].group_nt) {
            g->has_groups = true;
            break;
        }
    }

    n00b_nonterm_t *start = n00b_get_nonterm(g, g->default_start);

    if (start) {
        start->start_nt = true;
    }

    g->finalized = true;
}

// ============================================================================
// Earley analysis (lazy)
// ============================================================================

// Compute the Earley-only LR0 tables (items / states / predict states).
// These are NOT needed by PWZ, so they are intentionally NOT part of
// n00b_grammar_finalize() (which DOES compute the first-sets/left-corners
// PWZ prunes with) and run only when Earley is actually invoked (see
// n00b_earley_new). Idempotent and independent of `finalized`. The grammar
// MUST already be finalized — the LR0 construction relies on the first-set
// / valid-token / nullability state finalize builds; n00b_earley_new
// guarantees finalize ran first.
void
n00b_grammar_compute_earley_analysis(n00b_grammar_t *g)
{
    if (!g || g->earley_analysis_done) {
        return;
    }

    compute_lr0_items(g);
    build_lr0_states(g);
    lr0_compute_predict_states(g);

    g->earley_analysis_done = true;
}

// ============================================================================
// Keyword query
// ============================================================================

bool
n00b_grammar_is_keyword(n00b_grammar_t *g, n00b_string_t *text)
{
    if (!g || !g->terminal_map || !text || text->u8_bytes == 0) {
        return false;
    }

    bool           found = false;

    (void)n00b_dict_get(g->terminal_map, text, &found);

    return found;
}
