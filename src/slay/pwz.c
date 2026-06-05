// pwz.c - Parsing With Zippers (PWZ): derivative-based parser.
//
// Translates Darragh & Adams (ICFP 2020) from OCaml to C, integrating
// with n00b's grammar, tree, and walk-action infrastructure.
//
// The algorithm uses generalized zippers to traverse grammar expressions,
// handling arbitrary CFGs including ambiguous and left-recursive grammars.
//
// This is a faithful port of the ncc bootstrap implementation
// (~/ncc/src/parse/pwz.c): the algorithm and data model are kept verbatim
// (memo refcounting + recycle free list, in_progress packed into end_pos
// bit 31, single-memo left recursion, last-alternative tree extraction).
// Only the primitives differ — n00b allocation, n00b typed lists/dicts,
// and the two-pool memory model documented in pwz_internal.h.

#include "slay/pwz.h"
#include "slay/parse_tree.h"
#include "slay/annotation.h"
#include "internal/slay/pwz_internal.h"
#include "internal/slay/grammar_internal.h"
#include "internal/slay/unicode_class.h"
#include "text/unicode/encoding.h"
#include "core/alloc.h"
#include "core/runtime.h"
#include "adt/array.h"
#include "adt/list.h"
#include "text/strings/string_ops.h"
#include "parsers/token_stream.h"

#include <assert.h>
#include <string.h>

// ============================================================================
// Token access helpers (via shared stream)
// ============================================================================

static inline n00b_token_info_t *
get_token(n00b_pwz_parser_t *p, int32_t pos)
{
    return n00b_stream_get(p->stream, pos);
}

// ============================================================================
// Per-parse allocation helpers (parse_pool — the ncc parse_arena analog)
// ============================================================================

static pwz_mem_t *
alloc_mem(n00b_pwz_parser_t *p)
{
    pwz_mem_t *m;

    if (p->free_mems) {
        m            = p->free_mems;
        p->free_mems = (pwz_mem_t *)m->parents;
    }
    else {
        m = n00b_alloc_with_opts(pwz_mem_t, N00B_ALLOC_OPTS(p->parse_allocator));
    }

    m->parents   = NULL;
    m->result    = p->exp_bottom;
    m->start_pos = PWZ_POS_BOTTOM;
    m->end_pos   = PWZ_POS_BOTTOM;
    m->refcount  = 1;

    return m;
}

static inline pwz_mem_t *
mem_retain(pwz_mem_t *m)
{
    if (m) {
        m->refcount++;
    }
    return m;
}

static void mem_release(n00b_pwz_parser_t *p, pwz_mem_t *m);

// Release a context's memo reference.
static inline void
cxt_release_mem(n00b_pwz_parser_t *p, pwz_cxt_t *c)
{
    switch (c->kind) {
    case PWZ_CXT_SEQ:
        mem_release(p, c->seq.mem);
        break;
    case PWZ_CXT_ALT:
        mem_release(p, c->alt.mem);
        break;
    case PWZ_CXT_TOP:
        break;
    }
}

static void
mem_release(n00b_pwz_parser_t *p, pwz_mem_t *m)
{
    if (!m || --m->refcount > 0) {
        return;
    }
    // Cascade: release all contexts in the parent chain, which in turn
    // release the memos they reference.
    pwz_cxt_node_t *node = m->parents;
    while (node) {
        pwz_cxt_node_t *next = node->next;
        cxt_release_mem(p, node->cxt);
        node = next;
    }
    // Return to free list (reuse m->parents as the next link).
    m->parents   = (pwz_cxt_node_t *)p->free_mems;
    p->free_mems = m;
}

static pwz_cxt_t *
alloc_cxt(n00b_pwz_parser_t *p)
{
    pwz_cxt_t *c = n00b_alloc_with_opts(pwz_cxt_t,
                                        N00B_ALLOC_OPTS(p->parse_allocator));
    *c = (pwz_cxt_t){0};
    return c;
}

static pwz_cxt_node_t *
alloc_cxt_node(n00b_pwz_parser_t *p, pwz_cxt_t *cxt, pwz_cxt_node_t *next)
{
    pwz_cxt_node_t *n = n00b_alloc_with_opts(pwz_cxt_node_t,
                                             N00B_ALLOC_OPTS(p->parse_allocator));
    n->cxt  = cxt;
    n->next = next;

    return n;
}

static pwz_exp_t *
alloc_result_exp(n00b_pwz_parser_t *p)
{
    return n00b_alloc_with_opts(pwz_exp_t, N00B_ALLOC_OPTS(p->parse_allocator));
}

static inline pwz_exp_ptr_t *
alloc_child_array(n00b_pwz_parser_t *p, int32_t n)
{
    return n00b_alloc_array_with_opts(pwz_exp_ptr_t, n,
                                      N00B_ALLOC_OPTS(p->parse_allocator));
}

// ============================================================================
// Grammar-graph allocation helpers (grammar_pool — non-moving, hidden)
// ============================================================================

// Copy a nonterm name into the non-moving grammar pool. seq.name is a raw
// `const char *` into a grammar n00b_string's data buffer, which lives in
// the MOVING arena. It is copied onto result exps (in the hidden,
// unscanned parse pool), so a raw pointer would dangle once the GC
// relocates the string. Interning keeps every seq.name valid for the
// parser's lifetime without scanning either pool.
static const char *
intern_name(n00b_pwz_parser_t *p, const char *name)
{
    if (!name) {
        return NULL;
    }

    size_t len  = strlen(name) + 1;
    char  *copy = n00b_alloc_array_with_opts(char, len,
                                             N00B_ALLOC_OPTS(p->grammar_allocator));
    memcpy(copy, name, len);
    return copy;
}

// ============================================================================
// Track grammar exp nodes for per-parse memo reset
// ============================================================================

static void
register_exp(n00b_pwz_parser_t *p, pwz_exp_t *e)
{
    n00b_list_push(p->all_exps, e);
}

// ============================================================================
// Grammar -> Exp conversion
// ============================================================================

static pwz_exp_t *
make_tok_exp(n00b_pwz_parser_t *p, int64_t tid)
{
    pwz_exp_t *e = n00b_alloc_with_opts(pwz_exp_t,
                                        N00B_ALLOC_OPTS(p->grammar_allocator));
    e->kind = PWZ_TOK;
    e->tid  = tid;

    register_exp(p, e);
    return e;
}

static pwz_exp_t *
make_class_exp(n00b_pwz_parser_t *p, n00b_char_class_t cc)
{
    pwz_exp_t *e = n00b_alloc_with_opts(pwz_exp_t,
                                        N00B_ALLOC_OPTS(p->grammar_allocator));
    e->kind = PWZ_CLASS;
    e->cc   = cc;

    register_exp(p, e);
    return e;
}

static pwz_exp_t *
make_any_exp(n00b_pwz_parser_t *p)
{
    pwz_exp_t *e = n00b_alloc_with_opts(pwz_exp_t,
                                        N00B_ALLOC_OPTS(p->grammar_allocator));
    e->kind = PWZ_ANY;

    register_exp(p, e);
    return e;
}

static pwz_exp_t *
make_seq_exp(n00b_pwz_parser_t *p,
             const char        *name,
             int64_t            nt_id,
             int32_t            rule_ix,
             pwz_exp_ptr_t     *children,
             int32_t            nchildren)
{
    pwz_exp_t *e = n00b_alloc_with_opts(pwz_exp_t,
                                        N00B_ALLOC_OPTS(p->grammar_allocator));
    e->kind          = PWZ_SEQ;
    e->seq.name      = name;  // already interned by the caller (p->nt_names)
    e->nt_id         = nt_id;
    e->rule_ix       = rule_ix;
    e->seq.children  = children;
    e->nchildren     = nchildren;

    register_exp(p, e);
    return e;
}

static pwz_exp_t *
make_alt_exp(n00b_pwz_parser_t *p, int64_t nt_id)
{
    pwz_exp_t *e = n00b_alloc_with_opts(pwz_exp_t,
                                        N00B_ALLOC_OPTS(p->grammar_allocator));
    e->kind     = PWZ_ALT;
    e->nt_id    = nt_id;
    e->alt.alts = n00b_list_new_private(pwz_exp_ptr_t,
                                        .allocator = p->grammar_allocator);
    register_exp(p, e);
    return e;
}

static void
alt_add(pwz_exp_t *alt, pwz_exp_t *child)
{
    n00b_list_push(alt->alt.alts, child);
}

// Build exp children from a rule's contents list, resolving NT references
// to the pre-allocated Alt nodes.
static void
build_seq_children(n00b_pwz_parser_t *p,
                   n00b_parse_rule_t *rule,
                   pwz_exp_ptr_t    **out_children,
                   int32_t           *out_count)
{
    size_t n = n00b_list_len(rule->contents);

    // Count non-empty items first.
    int32_t count = 0;

    for (size_t i = 0; i < n; i++) {
        n00b_match_t *item = &rule->contents.data[i];

        if (item->kind != N00B_MATCH_EMPTY) {
            count++;
        }
    }

    if (count == 0) {
        *out_children = NULL;
        *out_count    = 0;
        return;
    }

    pwz_exp_ptr_t *children = n00b_alloc_array_with_opts(
        pwz_exp_ptr_t, count, N00B_ALLOC_OPTS(p->grammar_allocator));
    int32_t ix = 0;

    for (size_t i = 0; i < n; i++) {
        n00b_match_t *item = &rule->contents.data[i];

        switch (item->kind) {
        case N00B_MATCH_NT:
            children[ix++] = p->nt_exps[item->nt_id];
            break;

        case N00B_MATCH_TERMINAL:
            children[ix++] = make_tok_exp(p, item->terminal_id);
            break;

        case N00B_MATCH_CLASS:
            children[ix++] = make_class_exp(p, item->char_class);
            break;

        case N00B_MATCH_ANY:
            children[ix++] = make_any_exp(p);
            break;

        case N00B_MATCH_GROUP: {
            n00b_rule_group_t *grp = (n00b_rule_group_t *)item->group;
            children[ix++]         = p->nt_exps[grp->contents_id];
            break;
        }

        case N00B_MATCH_EMPTY:
        case N00B_MATCH_SET:
            break;
        }
    }

    *out_children = children;
    *out_count    = ix;
}

// Handle EBNF group expansion for group NTs.
static void
expand_group_nt(n00b_pwz_parser_t *p, n00b_grammar_t *g, int64_t nt_id)
{
    n00b_nonterm_t *nt   = n00b_get_nonterm(g, nt_id);
    pwz_exp_t      *alt  = p->nt_exps[nt_id];
    const char     *name = p->nt_names[nt_id];

    // Find the rule_group that uses this NT as its contents.
    n00b_rule_group_t *grp = NULL;

    for (size_t i = 0; i < n00b_list_len(g->rules); i++) {
        n00b_parse_rule_t *rule = &g->rules.data[i];

        for (size_t j = 0; j < n00b_list_len(rule->contents); j++) {
            n00b_match_t *item = &rule->contents.data[j];

            if (item->kind == N00B_MATCH_GROUP) {
                n00b_rule_group_t *rg = (n00b_rule_group_t *)item->group;

                if (rg->contents_id == nt_id) {
                    grp = rg;
                    break;
                }
            }
        }

        if (grp) {
            break;
        }
    }

    if (!grp) {
        // Couldn't find group info. Just build normally from rules.
        for (size_t i = 0; i < n00b_list_len(nt->rule_ids); i++) {
            int32_t            rule_ix = nt->rule_ids.data[i];
            n00b_parse_rule_t *rule    = n00b_get_rule(g, rule_ix);

            if (rule->penalty_rule) {
                continue;
            }

            pwz_exp_ptr_t *children;
            int32_t        nchildren;

            build_seq_children(p, rule, &children, &nchildren);

            pwz_exp_t *seq = make_seq_exp(p, name, nt_id, (int32_t)i,
                                          children, nchildren);
            alt_add(alt, seq);
        }

        return;
    }

    // Build body alt from the group NT's own rules.
    pwz_exp_t *body_alt = make_alt_exp(p, nt_id);

    for (size_t i = 0; i < n00b_list_len(nt->rule_ids); i++) {
        int32_t            rule_ix = nt->rule_ids.data[i];
        n00b_parse_rule_t *rule    = n00b_get_rule(g, rule_ix);

        if (rule->penalty_rule) {
            continue;
        }

        pwz_exp_ptr_t *children;
        int32_t        nchildren;

        build_seq_children(p, rule, &children, &nchildren);

        pwz_exp_t *seq = make_seq_exp(p, name, nt_id, (int32_t)i,
                                      children, nchildren);
        alt_add(body_alt, seq);
    }

    // Empty seq (matches epsilon).
    pwz_exp_t *empty_seq = make_seq_exp(p, name, nt_id, -1, NULL, 0);

    size_t body_nalts = n00b_list_len(body_alt->alt.alts);

    if (grp->min == 0 && grp->max == 1) {
        // Optional: Alt(body, empty)
        for (size_t i = 0; i < body_nalts; i++) {
            alt_add(alt, body_alt->alt.alts.data[i]);
        }

        alt_add(alt, empty_seq);
    }
    else if (grp->min == 0 && grp->max == 0) {
        // Star (left-recursive): Alt(Seq(self, body), empty)
        // Left-recursion lets PWZ's seed-growing handle repetition with a
        // single memo, avoiding O(n) parent-chain depth.
        for (size_t i = 0; i < body_nalts; i++) {
            pwz_exp_t *body_seq = body_alt->alt.alts.data[i];
            int32_t    nc       = body_seq->nchildren;
            int32_t    new_nc   = nc + 1;

            pwz_exp_ptr_t *new_children = n00b_alloc_array_with_opts(
                pwz_exp_ptr_t, new_nc, N00B_ALLOC_OPTS(p->grammar_allocator));
            new_children[0] = alt; // self-reference (left-recursive)
            memcpy(new_children + 1, body_seq->seq.children,
                   (size_t)nc * sizeof(pwz_exp_ptr_t));

            pwz_exp_t *rep_seq = make_seq_exp(p, name, nt_id,
                                              body_seq->rule_ix,
                                              new_children, new_nc);
            alt_add(alt, rep_seq);
        }

        alt_add(alt, empty_seq);
    }
    else if (grp->min == 1 && grp->max == 0) {
        // Plus (left-recursive): Alt(Seq(self, body), body)
        // Left-recursion lets PWZ's seed-growing handle repetition with a
        // single memo, avoiding O(n) parent-chain depth.
        for (size_t i = 0; i < body_nalts; i++) {
            pwz_exp_t *body_seq = body_alt->alt.alts.data[i];
            int32_t    nc       = body_seq->nchildren;
            int32_t    new_nc   = nc + 1;

            pwz_exp_ptr_t *new_children = n00b_alloc_array_with_opts(
                pwz_exp_ptr_t, new_nc, N00B_ALLOC_OPTS(p->grammar_allocator));
            new_children[0] = alt; // self-reference (left-recursive)
            memcpy(new_children + 1, body_seq->seq.children,
                   (size_t)nc * sizeof(pwz_exp_ptr_t));

            pwz_exp_t *rep_seq = make_seq_exp(p, name, nt_id,
                                              body_seq->rule_ix,
                                              new_children, new_nc);
            alt_add(alt, rep_seq);
        }

        // Base case: just the body itself.
        for (size_t i = 0; i < body_nalts; i++) {
            alt_add(alt, body_alt->alt.alts.data[i]);
        }
    }
    else {
        // General case: just use the body rules directly.
        for (size_t i = 0; i < body_nalts; i++) {
            alt_add(alt, body_alt->alt.alts.data[i]);
        }
    }
}

static void
build_exp_graph(n00b_pwz_parser_t *p, n00b_grammar_t *g)
{
    int32_t num_nts = (int32_t)n00b_list_len(g->nt_list);

    p->nt_exps  = n00b_alloc_array_with_opts(
        pwz_exp_ptr_t, num_nts, N00B_ALLOC_OPTS(p->grammar_allocator));
    p->nt_names = n00b_alloc_array_with_opts(
        const char *, num_nts, N00B_ALLOC_OPTS(p->grammar_allocator));

    // Phase 1: Create one Alt node per NT (handles forward refs / cycles)
    // and intern each NT's name into the non-moving grammar pool.
    for (int32_t i = 0; i < num_nts; i++) {
        n00b_nonterm_t *nt = n00b_get_nonterm(g, i);

        p->nt_names[i] = intern_name(p, (nt && nt->name) ? nt->name->data : NULL);
        p->nt_exps[i]  = make_alt_exp(p, i);
    }

    // Phase 2: Populate each Alt with Seq children from rules.
    for (int32_t i = 0; i < num_nts; i++) {
        n00b_nonterm_t *nt = n00b_get_nonterm(g, i);

        if (nt->group_nt) {
            expand_group_nt(p, g, i);
            continue;
        }

        pwz_exp_t *alt_node = p->nt_exps[i];

        for (size_t j = 0; j < n00b_list_len(nt->rule_ids); j++) {
            int32_t            rule_ix = nt->rule_ids.data[j];
            n00b_parse_rule_t *rule    = n00b_get_rule(g, rule_ix);

            if (rule->penalty_rule) {
                continue;
            }

            pwz_exp_ptr_t *children;
            int32_t        nchildren;

            build_seq_children(p, rule, &children, &nchildren);

            pwz_exp_t *seq = make_seq_exp(p, p->nt_names[i], (int64_t)i,
                                          (int32_t)j, children, nchildren);
            alt_add(alt_node, seq);
        }
    }

    p->start_exp = p->nt_exps[g->default_start];
}

// ============================================================================
// Per-parse memo initialization / reset
// ============================================================================

static void
reset_memos(n00b_pwz_parser_t *p)
{
    size_t num = n00b_list_len(p->all_exps);

    for (size_t i = 0; i < num; i++) {
        mem_release(p, p->all_exps.data[i]->mem);
        p->all_exps.data[i]->mem = NULL;
    }
}

// ============================================================================
// FIRST-set filtering
// ============================================================================

static inline bool
nt_first_matches(n00b_nonterm_t *nt, int64_t token_id)
{
    if (nt->first_has_any) {
        return true;
    }

    if (!nt->first_set || nt->first_set->length == 0) {
        return true;
    }

    return n00b_dict_contains(nt->first_set, token_id);
}

static inline bool
rule_first_matches(n00b_parse_rule_t *rule, int64_t token_id)
{
    if (rule->first_has_any) {
        return true;
    }

    if (!rule->first_set || rule->first_set->length == 0) {
        return true;
    }

    return n00b_dict_contains(rule->first_set, token_id);
}

// ============================================================================
// Core derive functions
// ============================================================================

static void
d_d(n00b_pwz_parser_t *p, int32_t pos, n00b_token_info_t *tok,
    pwz_cxt_t *cxt, pwz_exp_t *exp);
static void
d_d_prime(n00b_pwz_parser_t *p, int32_t pos, n00b_token_info_t *tok,
          pwz_mem_t *mem, pwz_exp_t *exp);
static void
d_u(n00b_pwz_parser_t *p, int32_t pos, pwz_exp_t *result, pwz_mem_t *mem);
static void
d_u_prime(n00b_pwz_parser_t *p, int32_t pos, pwz_exp_t *result, pwz_cxt_t *cxt);

static bool
token_matches(n00b_token_info_t *tok, pwz_exp_t *exp)
{
    if (!tok) {
        return false;
    }

    switch (exp->kind) {
    case PWZ_TOK:
        return tok->tid == exp->tid;

    case PWZ_CLASS:
        return n00b_codepoint_matches_class(tok->tid, exp->cc);

    case PWZ_ANY:
        return true;

    default:
        return false;
    }
}

static void
d_d(n00b_pwz_parser_t *p, int32_t pos, n00b_token_info_t *tok,
    pwz_cxt_t *cxt, pwz_exp_t *exp)
{
    if (exp->mem && exp->mem->start_pos == pos) {
        exp->mem->parents = alloc_cxt_node(p, cxt, exp->mem->parents);

        if (pwz_mem_end_pos(exp->mem) != PWZ_POS_BOTTOM) {
            d_u_prime(p, pwz_mem_end_pos(exp->mem), exp->mem->result, cxt);
        }

        return;
    }

    mem_release(p, exp->mem);  // drop old memo ref (if any)

    pwz_mem_t *mem = alloc_mem(p);

    mem->start_pos = pos;
    mem->parents   = alloc_cxt_node(p, cxt, NULL);
    exp->mem       = mem;  // takes the initial refcount=1

    d_d_prime(p, pos, tok, mem, exp);
}

static void
d_d_prime(n00b_pwz_parser_t *p, int32_t pos, n00b_token_info_t *tok,
          pwz_mem_t *mem, pwz_exp_t *exp)
{
    switch (exp->kind) {
    case PWZ_TOK:
    case PWZ_CLASS:
    case PWZ_ANY:
        if (token_matches(tok, exp)) {
            pwz_exp_t *result = alloc_result_exp(p);

            result->kind = exp->kind;
            result->tid  = tok->tid;

            n00b_list_push(p->worklist_swap,
                           ((pwz_zipper_t){.result = result,
                                           .mem    = mem_retain(mem)}));
        }

        break;

    case PWZ_SEQ:
        if (exp->nchildren == 0) {
            pwz_exp_t *result = alloc_result_exp(p);

            result->kind         = PWZ_SEQ;
            result->seq.name     = exp->seq.name;
            result->nt_id        = exp->nt_id;
            result->rule_ix      = exp->rule_ix;
            result->seq.children = NULL;
            result->nchildren    = 0;

            d_u(p, pos, result, mem);
        }
        else {
            // Store parent memo directly on SeqC; on completion, d_u_prime
            // routes directly to the parent memo.
            pwz_cxt_t *seq_cxt = alloc_cxt(p);

            seq_cxt->kind       = PWZ_CXT_SEQ;
            seq_cxt->seq.mem    = mem_retain(mem);
            seq_cxt->nt_id      = exp->nt_id;
            seq_cxt->rule_ix    = exp->rule_ix;
            seq_cxt->seq.left   = NULL;
            seq_cxt->nleft      = 0;
            seq_cxt->seq.right  = exp->seq.children + 1;
            seq_cxt->seq.nright = exp->nchildren - 1;

            d_d(p, pos, tok, seq_cxt, exp->seq.children[0]);
        }

        break;

    case PWZ_ALT: {
        // FIRST-set filtering.
        if (tok && exp->nt_id >= 0) {
            n00b_nonterm_t *nt = n00b_get_nonterm(p->grammar, exp->nt_id);

            if (nt && !nt->group_nt && !nt_first_matches(nt, tok->tid)) {
                break;
            }
        }

        bool can_filter_alts = false;

        if (tok && exp->nt_id >= 0) {
            n00b_nonterm_t *nt = n00b_get_nonterm(p->grammar, exp->nt_id);

            if (nt && !nt->group_nt) {
                can_filter_alts = true;
            }
        }

        size_t nalts = n00b_list_len(exp->alt.alts);

        for (size_t i = 0; i < nalts; i++) {
            pwz_exp_t *alt_child = exp->alt.alts.data[i];

            if (can_filter_alts && alt_child->kind == PWZ_SEQ
                && alt_child->nt_id >= 0 && alt_child->rule_ix >= 0) {
                n00b_nonterm_t *nt = n00b_get_nonterm(p->grammar,
                                                      alt_child->nt_id);

                if (nt && alt_child->rule_ix < (int32_t)n00b_list_len(nt->rule_ids)) {
                    int32_t            rix  = nt->rule_ids.data[alt_child->rule_ix];
                    n00b_parse_rule_t *rule = n00b_get_rule(p->grammar, rix);

                    if (rule && !rule_first_matches(rule, tok->tid)) {
                        continue;
                    }
                }
            }

            pwz_cxt_t *alt_cxt = alloc_cxt(p);

            alt_cxt->kind    = PWZ_CXT_ALT;
            alt_cxt->alt.mem = mem_retain(mem);

            d_d(p, pos, tok, alt_cxt, alt_child);
        }

        break;
    }
    }
}

static void
d_u(n00b_pwz_parser_t *p, int32_t pos, pwz_exp_t *result, pwz_mem_t *mem)
{
    int32_t ep = pwz_mem_end_pos(mem);

    if (ep != PWZ_POS_BOTTOM) {
        if (pos == ep) {
            // Same-position completion: accumulate ambiguity.
            pwz_exp_t *existing = mem->result;

            if (existing->kind == PWZ_ALT && existing->nt_id == -1) {
                n00b_list_push(existing->alt.alts, result);
            }
            else {
                pwz_exp_t *copy = alloc_result_exp(p);

                *copy = *existing;

                existing->kind     = PWZ_ALT;
                existing->nt_id    = -1;
                // Result-exp alt list lives in the (non-moving) parse pool,
                // alongside the result exps it holds.
                existing->alt.alts = n00b_list_new_private(
                    pwz_exp_ptr_t, .allocator = p->parse_allocator);
                n00b_list_push(existing->alt.alts, copy);
                n00b_list_push(existing->alt.alts, result);
            }

            return;
        }

        // Later-position completion (left-recursion grew the seed).
        // Skip if already propagating this memo (re-entrant guard).
        if (pwz_mem_in_progress(mem)) {
            return;
        }
    }

    // First completion, or longer left-recursive match.
    mem->end_pos = pos | PWZ_MEM_IN_PROGRESS_BIT;
    mem->result  = result;

    pwz_cxt_node_t *node = mem->parents;

    while (node) {
        d_u_prime(p, pos, result, node->cxt);
        node = node->next;
    }

    pwz_mem_set_in_progress(mem, false);
}

static void
d_u_prime(n00b_pwz_parser_t *p, int32_t pos, pwz_exp_t *result, pwz_cxt_t *cxt)
{
    switch (cxt->kind) {
    case PWZ_CXT_TOP:
        n00b_list_push(p->tops, result);
        break;

    case PWZ_CXT_SEQ: {
        if (cxt->seq.nright == 0) {
            int32_t total = cxt->nleft + 1;

            pwz_exp_ptr_t *children = alloc_child_array(p, total);

            for (int32_t i = 0; i < cxt->nleft; i++) {
                children[i] = cxt->seq.left[i];
            }

            children[cxt->nleft] = result;

            pwz_exp_t *seq_result = alloc_result_exp(p);

            seq_result->kind         = PWZ_SEQ;
            seq_result->seq.name     = cxt->nt_id >= 0 ? p->nt_names[cxt->nt_id]
                                                       : NULL;
            seq_result->nt_id        = cxt->nt_id;
            seq_result->rule_ix      = cxt->rule_ix;
            seq_result->seq.children = children;
            seq_result->nchildren    = total;

            d_u(p, pos, seq_result, cxt->seq.mem);
        }
        else {
            // Paper: d_d (SeqC (m, s, e :: es_L, es_R)) e_R
            // Reuses the same memo m; no extra AltC wrapper.
            int32_t new_nleft = cxt->nleft + 1;

            pwz_exp_ptr_t *new_left = alloc_child_array(p, new_nleft);

            for (int32_t i = 0; i < cxt->nleft; i++) {
                new_left[i] = cxt->seq.left[i];
            }

            new_left[cxt->nleft] = result;

            pwz_cxt_t *new_seq_cxt = alloc_cxt(p);

            new_seq_cxt->kind       = PWZ_CXT_SEQ;
            new_seq_cxt->seq.mem    = mem_retain(cxt->seq.mem);
            new_seq_cxt->nt_id      = cxt->nt_id;
            new_seq_cxt->rule_ix    = cxt->rule_ix;
            new_seq_cxt->seq.left   = new_left;
            new_seq_cxt->nleft      = new_nleft;
            new_seq_cxt->seq.right  = cxt->seq.right + 1;
            new_seq_cxt->seq.nright = cxt->seq.nright - 1;

            d_d(p, pos, get_token(p, pos), new_seq_cxt, cxt->seq.right[0]);
        }

        break;
    }

    case PWZ_CXT_ALT:
        d_u(p, pos, result, cxt->alt.mem);
        break;
    }
}

// ============================================================================
// Parse loop
// ============================================================================

static void
init_parse(n00b_pwz_parser_t *p)
{
    reset_memos(p);
    n00b_list_clear(p->worklist);
    n00b_list_clear(p->worklist_swap);
    n00b_list_clear(p->tops);
    p->result_tree  = NULL;
    p->result_trees = (n00b_parse_tree_array_t){0};

    pwz_mem_t *mem_top = alloc_mem(p);

    mem_top->start_pos = 0;

    pwz_cxt_t *top_cxt = alloc_cxt(p);

    top_cxt->kind    = PWZ_CXT_TOP;
    mem_top->parents = alloc_cxt_node(p, top_cxt, NULL);

    pwz_cxt_t *alt_cxt = alloc_cxt(p);

    alt_cxt->kind    = PWZ_CXT_ALT;
    alt_cxt->alt.mem = mem_retain(mem_top);

    n00b_token_info_t *tok = get_token(p, 0);

    d_d(p, 0, tok, alt_cxt, p->start_exp);
}

static bool
run_parse(n00b_pwz_parser_t *p)
{
    if (n00b_list_len(p->tops) > 0 && n00b_stream_token_count(p->stream) == 0) {
        return true;
    }

    for (int32_t pos = 0;; pos++) {
        // Swap worklists.
        n00b_list_t(pwz_zipper_t) tmp = p->worklist;
        p->worklist                   = p->worklist_swap;
        p->worklist_swap              = tmp;
        n00b_list_clear(p->worklist_swap);
        n00b_list_clear(p->tops);

        size_t wl_len = n00b_list_len(p->worklist);

        if (wl_len == 0) {
            return false;
        }

        int32_t complete_pos = pos + 1;

        // Ensure the next token is available via lazy stream fill: d_u may
        // derive new items that call d_d at complete_pos.
        bool have_next = (n00b_stream_get(p->stream, complete_pos) != NULL);

        for (size_t i = 0; i < wl_len; i++) {
            pwz_zipper_t *z = &p->worklist.data[i];
            d_u(p, complete_pos, z->result, z->mem);
        }

        // Release worklist memo refs now that all zippers are consumed.
        for (size_t i = 0; i < wl_len; i++) {
            mem_release(p, p->worklist.data[i].mem);
        }

        if (!have_next) {
            // No more tokens — this was the last position.
            return n00b_list_len(p->tops) > 0;
        }
    }
}

// ============================================================================
// Tree construction helpers
// ============================================================================

static n00b_parse_tree_t *
make_token_node(n00b_token_info_t *tok)
{
    return n00b_tree_leaf(n00b_nt_node_t, n00b_token_info_t *, tok);
}

static n00b_parse_tree_t *
make_epsilon_node(int32_t pos)
{
    n00b_nt_node_t pn = {0};

    pn.name  = n00b_string_from_cstr("\xce\xb5"); // UTF-8 epsilon
    pn.id    = N00B_EMPTY_STRING;
    pn.start = pos;
    pn.end   = pos;

    return n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, pn);
}

static n00b_parse_tree_t *
make_nt_node(n00b_grammar_t *g, int64_t nt_id, int32_t rule_index,
             int32_t start, int32_t end)
{
    n00b_nonterm_t *nt = n00b_get_nonterm(g, nt_id);
    n00b_nt_node_t  pn = {0};

    pn.name       = (nt && nt->name->data) ? nt->name : n00b_string_from_cstr("?");
    pn.id         = nt_id;
    pn.rule_index = rule_index;
    pn.start      = start;
    pn.end        = end;

    return n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, pn);
}

static n00b_parse_tree_t *
make_group_node(const char *name, int32_t start, int32_t end)
{
    n00b_nt_node_t pn = {0};

    pn.name      = name ? n00b_string_from_cstr(name) : n00b_string_from_cstr("group");
    pn.id        = N00B_GROUP_ID;
    pn.group_top = true;
    pn.start     = start;
    pn.end       = end;

    return n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, pn);
}

// ============================================================================
// Result exp -> parse tree conversion
// ============================================================================

typedef struct {
    int32_t            pos;
    n00b_pwz_parser_t *parser;
} tree_convert_state_t;

static n00b_parse_tree_t *
convert_exp_to_tree(n00b_pwz_parser_t *p, pwz_exp_t *exp,
                    tree_convert_state_t *st)
{
    if (!exp || exp == p->exp_bottom) {
        return make_epsilon_node(st->pos);
    }

    switch (exp->kind) {
    case PWZ_TOK:
    case PWZ_CLASS:
    case PWZ_ANY: {
        n00b_token_info_t *tok = get_token(p, st->pos);

        if (!tok) {
            return make_epsilon_node(st->pos);
        }

        n00b_parse_tree_t *t = make_token_node(tok);

        st->pos++;
        return t;
    }

    case PWZ_SEQ: {
        int32_t start = st->pos;

        if (exp->nchildren == 0) {
            if (exp->nt_id >= 0) {
                n00b_nonterm_t *nt = n00b_get_nonterm(p->grammar, exp->nt_id);

                if (nt && nt->group_nt) {
                    return make_group_node(exp->seq.name, start, start);
                }

                return make_nt_node(p->grammar, exp->nt_id, exp->rule_ix,
                                    start, start);
            }

            return make_epsilon_node(start);
        }

        // Collect children into a temporary list.
        n00b_list_t(n00b_parse_tree_ptr_t) children
            = n00b_list_new_cap_private(n00b_parse_tree_ptr_t, exp->nchildren);

        for (int32_t i = 0; i < exp->nchildren; i++) {
            n00b_parse_tree_t *child = convert_exp_to_tree(p, exp->seq.children[i],
                                                           st);
            n00b_list_push(children, child);
        }

        int32_t end = st->pos;

        n00b_parse_tree_t *tree;

        if (exp->nt_id >= 0) {
            n00b_nonterm_t *nt = n00b_get_nonterm(p->grammar, exp->nt_id);

            if (nt && nt->group_nt) {
                tree = make_group_node(exp->seq.name, start, end);
            }
            else {
                tree = make_nt_node(p->grammar, exp->nt_id, exp->rule_ix,
                                    start, end);
            }
        }
        else {
            size_t nch = n00b_list_len(children);

            if (nch == 1) {
                n00b_parse_tree_t *result = children.data[0];
                n00b_list_free(children);
                return result;
            }

            n00b_nt_node_t pn = {0};

            pn.name  = exp->seq.name ? n00b_string_from_cstr(exp->seq.name)
                                     : n00b_string_from_cstr("?");
            pn.id    = exp->nt_id;
            pn.start = start;
            pn.end   = end;
            tree     = n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, pn);
        }

        size_t nch = n00b_list_len(children);

        for (size_t i = 0; i < nch; i++) {
            (void)n00b_tree_add_child(tree, children.data[i]);
        }

        n00b_list_free(children);

        return tree;
    }

    case PWZ_ALT: {
        size_t nalts = n00b_list_len(exp->alt.alts);

        if (nalts > 0) {
            return convert_exp_to_tree(p, exp->alt.alts.data[nalts - 1], st);
        }

        return make_epsilon_node(st->pos);
    }
    }

    return make_epsilon_node(st->pos);
}

static n00b_parse_tree_t *
build_result_tree(n00b_pwz_parser_t *p, pwz_exp_t *top_result)
{
    tree_convert_state_t st = {.pos = 0, .parser = p};

    return convert_exp_to_tree(p, top_result, &st);
}

// Count the number of trees in an ambiguity forest.
static int32_t
count_trees_in_exp(pwz_exp_t *exp)
{
    if (!exp) {
        return 1;
    }

    if (exp->kind == PWZ_ALT && exp->nt_id == -1) {
        int32_t total = 0;
        size_t  nalts = n00b_list_len(exp->alt.alts);

        for (size_t i = 0; i < nalts; i++) {
            total += count_trees_in_exp(exp->alt.alts.data[i]);
        }

        return total;
    }

    if (exp->kind == PWZ_SEQ) {
        int32_t product = 1;

        for (int32_t i = 0; i < exp->nchildren; i++) {
            product *= count_trees_in_exp(exp->seq.children[i]);
        }

        return product;
    }

    return 1;
}

static pwz_exp_t *
find_top_ambiguity(pwz_exp_t *exp)
{
    if (!exp) {
        return NULL;
    }

    if (exp->kind == PWZ_ALT && exp->nt_id == -1) {
        return exp;
    }

    if (exp->kind == PWZ_SEQ && exp->nt_id == -1 && exp->nchildren == 1) {
        return find_top_ambiguity(exp->seq.children[0]);
    }

    return NULL;
}

static void
enumerate_trees(n00b_pwz_parser_t     *p,
                pwz_exp_t             *top_result,
                n00b_parse_tree_ptr_t **out,
                int32_t               *out_count)
{
    int32_t total = count_trees_in_exp(top_result);

    if (total <= 1) {
        *out_count = 1;
        *out       = n00b_alloc_array(n00b_parse_tree_ptr_t, 1);
        (*out)[0]  = build_result_tree(p, top_result);
        return;
    }

    pwz_exp_t *amb = find_top_ambiguity(top_result);

    if (amb) {
        size_t nalts = n00b_list_len(amb->alt.alts);

        *out_count = (int32_t)nalts;
        *out       = n00b_alloc_array(n00b_parse_tree_ptr_t, nalts);

        for (size_t i = 0; i < nalts; i++) {
            tree_convert_state_t st = {.pos = 0, .parser = p};
            (*out)[i] = convert_exp_to_tree(p, amb->alt.alts.data[i], &st);
        }

        return;
    }

    *out_count = 1;
    *out       = n00b_alloc_array(n00b_parse_tree_ptr_t, 1);
    (*out)[0]  = build_result_tree(p, top_result);
}

// ============================================================================
// Public API
// ============================================================================

n00b_pwz_parser_t *
n00b_pwz_new(n00b_grammar_t *g)
{
    n00b_grammar_finalize(g);

    /* Allocate the parser from the runtime's non-moving runtime_obj_pool so
     * the embedded pool structs (and the allocator pointers into them) stay
     * valid across collections; the GC otherwise relocates heap objects. */
    n00b_runtime_t    *rt = n00b_get_runtime();
    n00b_pwz_parser_t *p  = n00b_alloc_with_opts(
        n00b_pwz_parser_t,
        N00B_ALLOC_OPTS((n00b_allocator_t *)&rt->runtime_obj_pool));

    p->grammar = g;

    /* Grammar exp graph pool: non-moving, hidden. Nothing inside points
     * into the moving arena (names interned here, alt lists allocated
     * here), so it never needs scanning. */
    p->grammar_allocator = n00b_pool_init(&p->grammar_pool,
                                          .name   = "pwz-grammar",
                                          .hidden = true);

    p->all_exps      = n00b_list_new_private(pwz_exp_ptr_t);
    p->worklist      = n00b_list_new_private(pwz_zipper_t);
    p->worklist_swap = n00b_list_new_private(pwz_zipper_t);
    p->tops          = n00b_list_new_private(pwz_exp_ptr_t);

    // Sentinel nodes (grammar pool — persistent, never recycled).
    p->exp_bottom       = n00b_alloc_with_opts(
        pwz_exp_t, N00B_ALLOC_OPTS(p->grammar_allocator));
    p->exp_bottom->kind = PWZ_SEQ;

    p->mem_bottom            = n00b_alloc_with_opts(
        pwz_mem_t, N00B_ALLOC_OPTS(p->grammar_allocator));
    p->mem_bottom->start_pos = PWZ_POS_BOTTOM;
    p->mem_bottom->end_pos   = PWZ_POS_BOTTOM;

    build_exp_graph(p, g);

    return p;
}

void
n00b_pwz_free(n00b_pwz_parser_t *p)
{
    if (!p) {
        return;
    }

    reset_memos(p);

    /* The per-parse pool and the grammar graph pool bulk-free everything
     * they hold (memos, contexts, result exps, child arrays; exp nodes,
     * nt_exps, nt_names, interned names, alt lists, sentinels). */
    if (p->parse_pool_initialized) {
        n00b_allocator_destroy(p->parse_allocator);
        p->parse_pool_initialized = false;
    }
    n00b_allocator_destroy(p->grammar_allocator);

    n00b_list_free(p->all_exps);
    n00b_list_free(p->worklist);
    n00b_list_free(p->worklist_swap);
    n00b_list_free(p->tops);

    if (p->result_trees.data) {
        n00b_array_free(p->result_trees);
    }

    n00b_free(p);
}

void
n00b_pwz_reset(n00b_pwz_parser_t *p)
{
    // Drop memo refs / clear exp->mem before tearing down the parse pool
    // they live in.
    reset_memos(p);

    if (p->parse_pool_initialized) {
        n00b_allocator_destroy(p->parse_allocator);
    }

    // Fresh per-parse pool (the ncc parse_arena reset analog).
    p->parse_allocator        = n00b_pool_init(&p->parse_pool,
                                               .name   = "pwz-parse",
                                               .hidden = true);
    p->parse_pool_initialized = true;
    p->free_mems              = NULL;

    n00b_list_clear(p->worklist);
    n00b_list_clear(p->worklist_swap);
    n00b_list_clear(p->tops);
    p->stream       = NULL;
    p->result_tree  = NULL;
    p->result_trees = (n00b_parse_tree_array_t){0};
}

bool
n00b_pwz_parse(n00b_pwz_parser_t *p, n00b_token_stream_t *ts)
{
    n00b_pwz_reset(p);

    p->stream = ts;

    // Ensure the first token is available for init_parse.
    n00b_stream_get(ts, 0);

    init_parse(p);
    bool ok = run_parse(p);

    if (ok && n00b_list_len(p->tops) > 0) {
        p->result_tree = build_result_tree(p, p->tops.data[0]);
        return true;
    }

    return false;
}

n00b_parse_tree_t *
n00b_pwz_get_tree(n00b_pwz_parser_t *p)
{
    return p->result_tree;
}

n00b_parse_tree_array_t
n00b_pwz_get_trees(n00b_pwz_parser_t *p)
{
    if (p->result_trees.data) {
        return p->result_trees;
    }

    size_t ntops = n00b_list_len(p->tops);

    if (ntops == 0) {
        p->result_trees = n00b_array_new(n00b_parse_tree_ptr_t, 0);
        return p->result_trees;
    }

    if (ntops == 1) {
        n00b_parse_tree_ptr_t *raw_trees = NULL;
        int32_t                raw_count = 0;

        enumerate_trees(p, p->tops.data[0], &raw_trees, &raw_count);

        p->result_trees = n00b_array_new(n00b_parse_tree_ptr_t, raw_count);

        for (int32_t i = 0; i < raw_count; i++) {
            n00b_array_set(p->result_trees, i, raw_trees[i]);
        }
    }
    else {
        p->result_trees = n00b_array_new(n00b_parse_tree_ptr_t, (int32_t)ntops);

        for (size_t i = 0; i < ntops; i++) {
            n00b_array_set(p->result_trees, (int32_t)i,
                           build_result_tree(p, p->tops.data[i]));
        }
    }

    return p->result_trees;
}

// ============================================================================
// Forest API
// ============================================================================

n00b_parse_forest_t
n00b_pwz_get_forest(n00b_pwz_parser_t *p)
{
    n00b_parse_tree_array_t trees = n00b_pwz_get_trees(p);

    return n00b_parse_forest_new(p->grammar, trees);
}

// ============================================================================
// One-shot parse (implements n00b_parse_fn_t)
// ============================================================================

n00b_parse_forest_t
n00b_pwz_parse_grammar(n00b_grammar_t *g, n00b_token_stream_t *ts)
{
    n00b_pwz_parser_t *p  = n00b_pwz_new(g);
    bool               ok = n00b_pwz_parse(p, ts);

    if (!ok) {
        n00b_pwz_free(p);
        return n00b_parse_forest_empty(g);
    }

    n00b_parse_forest_t forest = n00b_pwz_get_forest(p);

    // Transfer tree ownership to caller; clear so n00b_pwz_free won't free.
    p->result_trees = (n00b_parse_tree_array_t){0};
    n00b_pwz_free(p);

    return forest;
}
