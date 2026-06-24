#include "logic/asp_rule.h"
#include "logic/asp_engine.h"

#include <string.h>

#define RULE_BODY_INIT_CAP 4

void
n00b_dl_rule_builder_init(n00b_dl_rule_builder_t *b)
{
    *b = (typeof(*b)){};
    b->body     = n00b_alloc_array(n00b_dl_body_goal_t, RULE_BODY_INIT_CAP);
    b->body_cap = RULE_BODY_INIT_CAP;
}

static n00b_dl_sym_t *
copy_args(const n00b_dl_sym_t *args, int32_t arity)
{
    n00b_dl_sym_t *copy = n00b_alloc_array(n00b_dl_sym_t, arity);
    memcpy(copy, args, arity * sizeof(n00b_dl_sym_t));
    return copy;
}

void
n00b_dl_rule_builder_head(n00b_dl_rule_builder_t *b,
                            n00b_dl_rel_id_t        rel,
                            int32_t                 arity,
                            const n00b_dl_sym_t    *args)
{
    b->head.rel     = rel;
    b->head.arity   = arity;
    b->head.args    = copy_args(args, arity);
    b->head.negated = false;
}

void
n00b_dl_rule_builder_add(n00b_dl_rule_builder_t *b,
                           n00b_dl_rel_id_t        rel,
                           int32_t                 arity,
                           const n00b_dl_sym_t    *args,
                           bool                    negated)
{
    if (b->body_len >= b->body_cap) {
        int32_t             old_cap  = b->body_cap;
        int32_t             new_cap  = old_cap * 2;
        n00b_dl_body_goal_t *new_body = n00b_alloc_array(n00b_dl_body_goal_t,
                                                           new_cap);
        memcpy(new_body, b->body, old_cap * sizeof(n00b_dl_body_goal_t));
        n00b_free(b->body);
        b->body     = new_body;
        b->body_cap = new_cap;
    }

    b->body[b->body_len++] = n00b_variant_set(
        n00b_dl_body_goal_t,
        n00b_dl_literal_t,
        ((n00b_dl_literal_t){
            .rel     = rel,
            .arity   = arity,
            .args    = copy_args(args, arity),
            .negated = negated,
        }));
}

void
n00b_dl_rule_builder_add_builtin(n00b_dl_rule_builder_t *b,
                                   n00b_dl_builtin_t       builtin)
{
    if (b->body_len >= b->body_cap) {
        int32_t             old_cap  = b->body_cap;
        int32_t             new_cap  = old_cap * 2;
        n00b_dl_body_goal_t *new_body = n00b_alloc_array(n00b_dl_body_goal_t,
                                                           new_cap);
        memcpy(new_body, b->body, old_cap * sizeof(n00b_dl_body_goal_t));
        n00b_free(b->body);
        b->body     = new_body;
        b->body_cap = new_cap;
    }

    b->body[b->body_len++] = n00b_variant_set(n00b_dl_body_goal_t,
                                              n00b_dl_builtin_t,
                                              builtin);
}

n00b_dl_rule_t
n00b_dl_rule_builder_finish(n00b_dl_rule_builder_t *b)
{
    n00b_dl_rule_t rule;
    rule.head     = b->head;
    rule.body     = b->body;
    rule.body_len = b->body_len;
    rule.stratum  = -1;

    b->head     = (n00b_dl_literal_t){};
    b->body     = nullptr;
    b->body_len = 0;
    b->body_cap = 0;

    return rule;
}

void
n00b_dl_rule_free(n00b_dl_rule_t *rule)
{
    n00b_free(rule->head.args);
    for (int32_t i = 0; i < rule->body_len; i++) {
        n00b_dl_body_goal_t *goal = &rule->body[i];
        if (n00b_variant_is_type(*goal, n00b_dl_literal_t)) {
            n00b_free(n00b_variant_get(*goal, n00b_dl_literal_t).args);
        } else {
            n00b_dl_builtin_t builtin = n00b_variant_get(*goal,
                                                         n00b_dl_builtin_t);
            n00b_dl_expr_free(builtin.lhs);
            n00b_dl_expr_free(builtin.rhs);
        }
    }
    n00b_free(rule->body);
}
