// pwz.c - Parsing With Zippers (PWZ): derivative-based parser.
//
// Translates Darragh & Adams (ICFP 2020) from OCaml to C, integrating
// with n00b's grammar, tree, and walk-action infrastructure.
//
// The algorithm uses generalized zippers to traverse grammar expressions,
// handling arbitrary CFGs including ambiguous and left-recursive grammars.

#include "slay/pwz.h"
#include "slay/parse_tree.h"
#include "slay/annotation.h"
#include "internal/slay/pwz_internal.h"
#include "internal/slay/grammar_internal.h"
#include "internal/slay/unicode_class.h"
#include "text/unicode/encoding.h"
#include "core/alloc.h"
#include "core/gc.h"
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
// Per-parse allocation helpers
//
// WP-017: pwz_mem_t / pwz_cxt_t / pwz_cxt_node_t and result
// pwz_exp_t live in a per-parser hidden n00b_pool_t pool — they
// never outlive the parser, and GC scanning them every cycle was
// the dominant parse-time cost on real input. Pool initialized
// lazily on first allocation, destroyed by n00b_pwz_free. Mirrors
// ncc's per-parse arena algorithmically; uses n00b's supported
// pool API.
// ============================================================================

static inline void
ensure_pool(n00b_pwz_parser_t *p)
{
    if (!p->pool_initialized) {
        /* HIDDEN pool — GC doesn't walk its pages. Safe because
         * pool memory only points to other pool memory and to
         * grammar exps held alive via p->all_exps. */
        p->parse_allocator = n00b_pool_init(&p->parse_pool,
                                            .name   = "pwz-parse",
                                            .hidden = true);
        p->pool_initialized = true;
    }
}

static pwz_mem_t *
alloc_mem(n00b_pwz_parser_t *p)
{
    ensure_pool(p);
    pwz_mem_t *m = n00b_alloc_with_opts(pwz_mem_t, N00B_ALLOC_OPTS(p->parse_allocator));

    m->start_pos = PWZ_POS_BOTTOM;
    m->end_pos   = PWZ_POS_BOTTOM;
    m->result    = p->exp_bottom;

    return m;
}

static pwz_cxt_t *
alloc_cxt(n00b_pwz_parser_t *p)
{
    ensure_pool(p);
    return n00b_alloc_with_opts(pwz_cxt_t, N00B_ALLOC_OPTS(p->parse_allocator));
}

static pwz_cxt_node_t *
alloc_cxt_node(n00b_pwz_parser_t *p, pwz_cxt_t *cxt, pwz_cxt_node_t *next)
{
    ensure_pool(p);
    pwz_cxt_node_t *n = n00b_alloc_with_opts(pwz_cxt_node_t,
                                             N00B_ALLOC_OPTS(p->parse_allocator));

    n->cxt  = cxt;
    n->next = next;

    return n;
}

static pwz_exp_t *
alloc_result_exp(n00b_pwz_parser_t *p)
{
    /* Result exps are converted to n00b_parse_tree_t via
     * convert_exp_to_tree at parse-end; the conversion COPIES
     * into fresh parse-tree nodes (separate type). So result
     * exps don't outlive n00b_pwz_free → safe to pool. */
    ensure_pool(p);
    return n00b_alloc_with_opts(pwz_exp_t, N00B_ALLOC_OPTS(p->parse_allocator));
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
    pwz_exp_t *e = n00b_alloc(pwz_exp_t);

    e->kind    = PWZ_TOK;
    e->tok.tid = tid;

    register_exp(p, e);
    return e;
}

static pwz_exp_t *
make_class_exp(n00b_pwz_parser_t *p, n00b_char_class_t cc)
{
    pwz_exp_t *e = n00b_alloc(pwz_exp_t);

    e->kind   = PWZ_CLASS;
    e->cls.cc = cc;

    register_exp(p, e);
    return e;
}

static pwz_exp_t *
make_any_exp(n00b_pwz_parser_t *p)
{
    pwz_exp_t *e = n00b_alloc(pwz_exp_t);

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
    pwz_exp_t *e = n00b_alloc(pwz_exp_t);

    e->kind          = PWZ_SEQ;
    e->seq.name      = name;
    e->seq.nt_id     = nt_id;
    e->seq.rule_ix   = rule_ix;
    e->seq.children  = children;
    e->seq.nchildren = nchildren;

    register_exp(p, e);
    return e;
}

static pwz_exp_t *
make_alt_exp(n00b_pwz_parser_t *p, int64_t nt_id)
{
    pwz_exp_t *e = n00b_alloc(pwz_exp_t);

    e->kind      = PWZ_ALT;
    e->alt.nt_id = nt_id;
    e->alt.alts  = n00b_list_new_private(pwz_exp_ptr_t);

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

    pwz_exp_ptr_t *children = n00b_alloc_array(pwz_exp_ptr_t, count);
    int32_t        ix       = 0;

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
    n00b_nonterm_t *nt  = n00b_get_nonterm(g, nt_id);
    pwz_exp_t      *alt = p->nt_exps[nt_id];

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

            pwz_exp_t *seq = make_seq_exp(p, nt->name->data, nt_id, (int32_t)i,
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

        pwz_exp_t *seq = make_seq_exp(p, nt->name->data, nt_id, (int32_t)i,
                                      children, nchildren);
        alt_add(body_alt, seq);
    }

    // Empty seq (matches epsilon).
    pwz_exp_t *empty_seq = make_seq_exp(p, nt->name->data, nt_id, -1, NULL, 0);

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
        for (size_t i = 0; i < body_nalts; i++) {
            pwz_exp_t *body_seq = body_alt->alt.alts.data[i];
            int32_t    nc       = body_seq->seq.nchildren;
            int32_t    new_nc   = nc + 1;

            pwz_exp_ptr_t *new_children = n00b_alloc_array(pwz_exp_ptr_t, new_nc);
            new_children[0] = alt; // self-reference (left-recursive)
            memcpy(new_children + 1, body_seq->seq.children,
                   (size_t)nc * sizeof(pwz_exp_ptr_t));

            pwz_exp_t *rep_seq = make_seq_exp(p, nt->name->data, nt_id,
                                              body_seq->seq.rule_ix,
                                              new_children, new_nc);
            alt_add(alt, rep_seq);
        }

        alt_add(alt, empty_seq);
    }
    else if (grp->min == 1 && grp->max == 0) {
        // Plus (left-recursive): Alt(Seq(self, body), body)
        for (size_t i = 0; i < body_nalts; i++) {
            pwz_exp_t *body_seq = body_alt->alt.alts.data[i];
            int32_t    nc       = body_seq->seq.nchildren;
            int32_t    new_nc   = nc + 1;

            pwz_exp_ptr_t *new_children = n00b_alloc_array(pwz_exp_ptr_t, new_nc);
            new_children[0] = alt; // self-reference (left-recursive)
            memcpy(new_children + 1, body_seq->seq.children,
                   (size_t)nc * sizeof(pwz_exp_ptr_t));

            pwz_exp_t *rep_seq = make_seq_exp(p, nt->name->data, nt_id,
                                              body_seq->seq.rule_ix,
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

    p->nt_exps = n00b_alloc_array(pwz_exp_ptr_t, num_nts);

    // Phase 1: Create one Alt node per NT (handles forward refs / cycles).
    for (int32_t i = 0; i < num_nts; i++) {
        p->nt_exps[i] = make_alt_exp(p, i);
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

            pwz_exp_t *seq = make_seq_exp(p, nt->name->data, (int64_t)i,
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
        p->all_exps.data[i]->mem = NULL;
    }
}

// ============================================================================
// Core derive: d_d, d_d_prime, d_u, d_u_prime
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
d_d(n00b_pwz_parser_t *p, int32_t pos, n00b_token_info_t *tok, pwz_cxt_t *cxt, pwz_exp_t *exp);
static void d_d_prime(n00b_pwz_parser_t *p,
                      int32_t            pos,
                      n00b_token_info_t *tok,
                      pwz_mem_t         *mem,
                      pwz_exp_t         *exp);
static void d_u(n00b_pwz_parser_t *p, int32_t pos, pwz_exp_t *result, pwz_mem_t *mem);
static void d_u_prime(n00b_pwz_parser_t *p, int32_t pos, pwz_exp_t *result, pwz_cxt_t *cxt);

static bool
token_matches(n00b_token_info_t *tok, pwz_exp_t *exp)
{
    if (!tok) {
        return false;
    }

    switch (exp->kind) {
    case PWZ_TOK:
        return tok->tid == exp->tok.tid;

    case PWZ_CLASS:
        if (!n00b_option_is_set(tok->value)) {
            return false;
        }
        {
            n00b_string_t *val = n00b_option_get(tok->value);
            uint32_t       pos = 0;
            int32_t cp = n00b_unicode_utf8_decode(val->data, (uint32_t)val->u8_bytes, &pos);
            return cp >= 0 && n00b_codepoint_matches_class(cp, exp->cls.cc);
        }

    case PWZ_ANY:
        return true;

    default:
        return false;
    }
}

static void
d_d(n00b_pwz_parser_t *p, int32_t pos, n00b_token_info_t *tok, pwz_cxt_t *cxt, pwz_exp_t *exp)
{
    if (exp->mem && exp->mem->start_pos == pos) {
        exp->mem->parents = alloc_cxt_node(p, cxt, exp->mem->parents);

        if (exp->mem->end_pos != PWZ_POS_BOTTOM) {
            d_u_prime(p, exp->mem->end_pos, exp->mem->result, cxt);
        }

        return;
    }

    pwz_mem_t *mem = alloc_mem(p);

    mem->start_pos = pos;
    mem->parents   = alloc_cxt_node(p, cxt, NULL);
    exp->mem       = mem;

    d_d_prime(p, pos, tok, mem, exp);
}

static void
d_d_prime(n00b_pwz_parser_t *p,
          int32_t            pos,
          n00b_token_info_t *tok,
          pwz_mem_t         *mem,
          pwz_exp_t         *exp)
{
    switch (exp->kind) {
    case PWZ_TOK:
    case PWZ_CLASS:
    case PWZ_ANY:
        if (token_matches(tok, exp)) {
            pwz_exp_t *result = alloc_result_exp(p);

            result->kind    = exp->kind;
            result->tok.tid = tok->tid;

            n00b_list_push(p->worklist_swap, ((pwz_zipper_t){.result = result, .mem = mem}));
        }

        break;

    case PWZ_SEQ:
        if (exp->seq.nchildren == 0) {
            pwz_exp_t *result = alloc_result_exp(p);

            result->kind          = PWZ_SEQ;
            result->seq.name      = exp->seq.name;
            result->seq.nt_id     = exp->seq.nt_id;
            result->seq.rule_ix   = exp->seq.rule_ix;
            result->seq.children  = NULL;
            result->seq.nchildren = 0;

            d_u(p, pos, result, mem);
        }
        else {
            pwz_cxt_t *seq_cxt = alloc_cxt(p);

            seq_cxt->kind        = PWZ_CXT_SEQ;
            seq_cxt->seq.mem     = mem;
            seq_cxt->seq.name    = exp->seq.name;
            seq_cxt->seq.nt_id   = exp->seq.nt_id;
            seq_cxt->seq.rule_ix = exp->seq.rule_ix;
            seq_cxt->seq.left    = NULL;
            seq_cxt->seq.nleft   = 0;
            seq_cxt->seq.right   = exp->seq.children + 1;
            seq_cxt->seq.nright  = exp->seq.nchildren - 1;

            d_d(p, pos, tok, seq_cxt, exp->seq.children[0]);
        }

        break;

    case PWZ_ALT: {
        // FIRST-set filtering.
        if (tok && exp->alt.nt_id >= 0) {
            n00b_nonterm_t *nt = n00b_get_nonterm(p->grammar, exp->alt.nt_id);

            if (nt && !nt->group_nt && !nt_first_matches(nt, tok->tid)) {
                break;
            }
        }

        bool can_filter_alts = false;

        if (tok && exp->alt.nt_id >= 0) {
            n00b_nonterm_t *nt = n00b_get_nonterm(p->grammar, exp->alt.nt_id);

            /* WP-017: port ncc filter — filter per-rule even when
             * the outer NT has first_has_any. Without this, for
             * any nullable outer NT, n00b would skip the per-rule
             * filter and explore ALL alternatives, leading to
             * exponential blow-up on ambiguous grammars like C.
             * ncc's nt_first_matches already short-circuits true
             * when first_has_any, but the per-rule filter on
             * each alt's rule still prunes meaningfully. */
            if (nt && !nt->group_nt) {
                can_filter_alts = true;
            }
        }

        size_t nalts = n00b_list_len(exp->alt.alts);

        for (size_t i = 0; i < nalts; i++) {
            pwz_exp_t *alt_child = exp->alt.alts.data[i];

            if (can_filter_alts && alt_child->kind == PWZ_SEQ && alt_child->seq.nt_id >= 0
                && alt_child->seq.rule_ix >= 0) {
                n00b_nonterm_t *nt = n00b_get_nonterm(p->grammar, alt_child->seq.nt_id);

                if (nt && alt_child->seq.rule_ix < (int32_t)n00b_list_len(nt->rule_ids)) {
                    int32_t            rix  = nt->rule_ids.data[alt_child->seq.rule_ix];
                    n00b_parse_rule_t *rule = n00b_get_rule(p->grammar, rix);

                    if (rule && !rule_first_matches(rule, tok->tid)) {
                        continue;
                    }
                }
            }

            pwz_cxt_t *alt_cxt = alloc_cxt(p);

            alt_cxt->kind    = PWZ_CXT_ALT;
            alt_cxt->alt.mem = mem;

            d_d(p, pos, tok, alt_cxt, alt_child);
        }

        break;
    }
    }
}

static void
d_u(n00b_pwz_parser_t *p, int32_t pos, pwz_exp_t *result, pwz_mem_t *mem)
{
    if (mem->end_pos != PWZ_POS_BOTTOM) {
        if (pos == mem->end_pos) {
            // Same-position ambiguity: mutate in place.
            pwz_exp_t *existing = mem->result;

            if (existing->kind == PWZ_ALT && existing->alt.nt_id == -1) {
                n00b_list_push(existing->alt.alts, result);
            }
            else {
                pwz_exp_t *copy = alloc_result_exp(p);

                *copy = *existing;

                existing->kind      = PWZ_ALT;
                existing->alt.nt_id = -1;
                existing->alt.alts  = n00b_list_new_private(pwz_exp_ptr_t);
                n00b_list_push(existing->alt.alts, copy);
                n00b_list_push(existing->alt.alts, result);
            }

            return;
        }

        // Later-position completion (left-recursion grew the seed).
        // Skip if already propagating this memo (re-entrant guard).
        if (mem->in_progress) {
            return;
        }
    }

    // First completion, or longer left-recursive match.
    mem->end_pos     = pos;
    mem->result      = result;
    mem->in_progress = true;

    pwz_cxt_node_t *node = mem->parents;

    while (node) {
        d_u_prime(p, pos, result, node->cxt);
        node = node->next;
    }

    mem->in_progress = false;
}

static void
d_u_prime(n00b_pwz_parser_t *p, int32_t pos, pwz_exp_t *result, pwz_cxt_t *cxt)
{
    switch (cxt->kind) {
    case PWZ_CXT_TOP:
        n00b_list_push(p->tops, result);
        break;

    case PWZ_CXT_SEQ: {
        /* WP-017: children / new_left arrays go to the per-parse
         * pool (matching ncc's arena). Previously they went to GC
         * arena, which is why this code had 10 GC root register /
         * unregister operations per token-step. Now: zero. */
        ensure_pool(p);
        if (cxt->seq.nright == 0) {
            int32_t        total    = cxt->seq.nleft + 1;
            pwz_exp_ptr_t *children = n00b_alloc_array_with_opts(pwz_exp_ptr_t, total,
                                                        N00B_ALLOC_OPTS(p->parse_allocator));
            for (int32_t i = 0; i < cxt->seq.nleft; i++) {
                children[i] = cxt->seq.left[i];
            }
            children[cxt->seq.nleft] = result;

            pwz_exp_t *seq_result     = alloc_result_exp(p);
            seq_result->kind          = PWZ_SEQ;
            seq_result->seq.name      = cxt->seq.name;
            seq_result->seq.nt_id     = cxt->seq.nt_id;
            seq_result->seq.rule_ix   = cxt->seq.rule_ix;
            seq_result->seq.children  = children;
            seq_result->seq.nchildren = total;
            d_u(p, pos, seq_result, cxt->seq.mem);
        }
        else {
            int32_t        new_nleft = cxt->seq.nleft + 1;
            pwz_exp_ptr_t *new_left  = n00b_alloc_array_with_opts(pwz_exp_ptr_t,
                                                        new_nleft,
                                                        N00B_ALLOC_OPTS(p->parse_allocator));

            for (int32_t i = 0; i < cxt->seq.nleft; i++) {
                new_left[i] = cxt->seq.left[i];
            }

            new_left[cxt->seq.nleft] = result;

            pwz_cxt_t *new_seq_cxt   = alloc_cxt(p);

            new_seq_cxt->kind        = PWZ_CXT_SEQ;
            new_seq_cxt->seq.mem     = cxt->seq.mem;
            new_seq_cxt->seq.name    = cxt->seq.name;
            new_seq_cxt->seq.nt_id   = cxt->seq.nt_id;
            new_seq_cxt->seq.rule_ix = cxt->seq.rule_ix;
            new_seq_cxt->seq.left    = new_left;
            new_seq_cxt->seq.nleft   = new_nleft;
            new_seq_cxt->seq.right   = cxt->seq.right + 1;
            new_seq_cxt->seq.nright  = cxt->seq.nright - 1;
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
    alt_cxt->alt.mem = mem_top;

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

        // Check if there's a next token (drives the termination condition).
        n00b_token_info_t *next_check = n00b_stream_get(p->stream, complete_pos);
        bool               have_next  = (next_check != NULL);

        for (size_t i = 0; i < wl_len; i++) {
            pwz_zipper_t *z = &p->worklist.data[i];
            d_u(p, complete_pos, z->result, z->mem);
        }

        if (!have_next) {
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
make_nt_node(n00b_grammar_t *g, int64_t nt_id, int32_t rule_index, int32_t start, int32_t end)
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
convert_exp_to_tree(n00b_pwz_parser_t *p, pwz_exp_t *exp, tree_convert_state_t *st)
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

        if (exp->seq.nchildren == 0) {
            if (exp->seq.nt_id >= 0) {
                n00b_nonterm_t *nt = n00b_get_nonterm(p->grammar, exp->seq.nt_id);

                if (nt && nt->group_nt) {
                    return make_group_node(exp->seq.name, start, start);
                }

                return make_nt_node(p->grammar, exp->seq.nt_id, exp->seq.rule_ix, start, start);
            }

            return make_epsilon_node(start);
        }

        // Collect children into a temporary list.
        n00b_list_t(n00b_parse_tree_ptr_t) children
            = n00b_list_new_cap_private(n00b_parse_tree_ptr_t, exp->seq.nchildren);

        for (int32_t i = 0; i < exp->seq.nchildren; i++) {
            n00b_parse_tree_t *child = convert_exp_to_tree(p, exp->seq.children[i], st);
            n00b_list_push(children, child);
        }

        int32_t end = st->pos;

        n00b_parse_tree_t *tree;

        if (exp->seq.nt_id >= 0) {
            n00b_nonterm_t *nt = n00b_get_nonterm(p->grammar, exp->seq.nt_id);

            if (nt && nt->group_nt) {
                tree = make_group_node(exp->seq.name, start, end);
            }
            else {
                tree = make_nt_node(p->grammar, exp->seq.nt_id, exp->seq.rule_ix, start, end);
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
            pn.id    = exp->seq.nt_id;
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

        if (nalts == 0) {
            return make_epsilon_node(st->pos);
        }

        if (nalts == 1) {
            return convert_exp_to_tree(p, exp->alt.alts.data[0], st);
        }

        // Multiple ambiguous alternatives — convert all and pick the best
        // using the grammar's disambiguator.
        n00b_tree_disambig_fn_t disambig = n00b_get_disambiguator(p->grammar);

        n00b_parse_tree_t *best     = NULL;
        int32_t            best_pos = st->pos;

        for (size_t i = 0; i < nalts; i++) {
            int32_t            saved_pos = st->pos;
            n00b_parse_tree_t *candidate = convert_exp_to_tree(p, exp->alt.alts.data[i], st);

            if (!best || disambig(candidate, best) < 0) {
                best     = candidate;
                best_pos = st->pos;
            }

            // Restore position for the next alternative.
            if (i + 1 < nalts) {
                st->pos = saved_pos;
            }
        }

        st->pos = best_pos;

        return best;
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

    if (exp->kind == PWZ_ALT && exp->alt.nt_id == -1) {
        int32_t total = 0;
        size_t  nalts = n00b_list_len(exp->alt.alts);

        for (size_t i = 0; i < nalts; i++) {
            total += count_trees_in_exp(exp->alt.alts.data[i]);
        }

        return total;
    }

    if (exp->kind == PWZ_SEQ) {
        int32_t product = 1;

        for (int32_t i = 0; i < exp->seq.nchildren; i++) {
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

    if (exp->kind == PWZ_ALT && exp->alt.nt_id == -1) {
        return exp;
    }

    if (exp->kind == PWZ_SEQ && exp->seq.nt_id == -1 && exp->seq.nchildren == 1) {
        return find_top_ambiguity(exp->seq.children[0]);
    }

    return NULL;
}

static void
enumerate_trees(n00b_pwz_parser_t      *p,
                pwz_exp_t              *top_result,
                n00b_parse_tree_ptr_t **out,
                int32_t                *out_count)
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
            (*out)[i]               = convert_exp_to_tree(p, amb->alt.alts.data[i], &st);
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

    n00b_pwz_parser_t *p = n00b_alloc(n00b_pwz_parser_t);

    p->grammar       = g;
    p->all_exps      = n00b_list_new_private(pwz_exp_ptr_t);
    p->worklist      = n00b_list_new_private(pwz_zipper_t);
    p->worklist_swap = n00b_list_new_private(pwz_zipper_t);
    p->tops          = n00b_list_new_private(pwz_exp_ptr_t);

    // Sentinel nodes.
    p->exp_bottom       = n00b_alloc(pwz_exp_t);
    p->exp_bottom->kind = PWZ_SEQ;

    p->mem_bottom            = n00b_alloc(pwz_mem_t);
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

    n00b_pwz_reset(p);

    // Free grammar exp nodes.
    size_t num_exps = n00b_list_len(p->all_exps);

    for (size_t i = 0; i < num_exps; i++) {
        pwz_exp_t *e = p->all_exps.data[i];

        if (e->kind == PWZ_SEQ && e->seq.children) {
            n00b_free(e->seq.children);
        }
        else if (e->kind == PWZ_ALT) {
            n00b_list_free(e->alt.alts);
        }

        n00b_free(e);
    }

    n00b_list_free(p->all_exps);
    n00b_free(p->nt_exps);
    n00b_free(p->exp_bottom);
    n00b_free(p->mem_bottom);
    n00b_list_free(p->worklist);
    n00b_list_free(p->worklist_swap);
    n00b_list_free(p->tops);

    if (p->result_trees.data) {
        n00b_array_free(p->result_trees);
    }

    /* WP-017: destroy the per-parser pool, freeing all the
     * intermediate pwz_mem_t / pwz_cxt_t / pwz_cxt_node_t /
     * pwz_exp_t state in one bulk operation. Mirrors ncc's
     * parse_arena teardown. */
    if (p->pool_initialized) {
        n00b_allocator_destroy(p->parse_allocator);
        p->pool_initialized = false;
    }

    n00b_free(p);
}

void
n00b_pwz_reset(n00b_pwz_parser_t *p)
{
    reset_memos(p);
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

        if (raw_trees) {
            n00b_free(raw_trees);
        }
    }
    else {
        p->result_trees = n00b_array_new(n00b_parse_tree_ptr_t, (int32_t)ntops);

        for (size_t i = 0; i < ntops; i++) {
            n00b_array_set(p->result_trees, (int32_t)i, build_result_tree(p, p->tops.data[i]));
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

    // Tree nodes are GC-allocated and survive parser free.
    // Don't free result_trees — they're now owned by the caller.
    p->result_trees = (n00b_parse_tree_array_t){0};
    n00b_pwz_free(p);

    return forest;
}
