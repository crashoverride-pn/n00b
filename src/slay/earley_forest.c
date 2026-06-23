// earley_forest.c - Parse forest construction from Earley chart states.
//
// Builds a parse forest (list of ambiguous parse trees) from completed
// Earley items and/or BSR (Binary Subtree Representation) elements.
// Ported from slop's src/slay/parse_tree.c.

#include "slay/earley.h"
#include "slay/parse_forest.h"
#include "internal/slay/earley_internal.h"
#include "internal/slay/grammar_internal.h"
#include "parsers/token_stream.h"
#include "core/alloc.h"
#include "adt/list.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Pointer list type — thin wrapper around n00b_list_t(void*)
// ============================================================================

typedef n00b_list_t(void *) ptrlist_raw_t;

typedef struct {
    ptrlist_raw_t list;
} ptrlist_t;

static inline ptrlist_t *
ptrlist_new(void)
{
    ptrlist_t *l = n00b_alloc(ptrlist_t);

    l->list = n00b_list_new_private(void *);

    return l;
}

static inline void
ptrlist_push(ptrlist_t *l, void *item)
{
    n00b_list_push(l->list, item);
}

static inline void *
ptrlist_get(ptrlist_t *l, size_t i)
{
    if (!l || i >= l->list.len) {
        return NULL;
    }

    return n00b_list_get(l->list, i);
}

static inline void
ptrlist_set(ptrlist_t *l, size_t i, void *val)
{
    if (i >= l->list.len) {
        return;
    }

    n00b_list_set(l->list, i, val);
}

static inline size_t
ptrlist_len(ptrlist_t *l)
{
    return l ? l->list.len : 0;
}

static inline ptrlist_t *
ptrlist_copy(ptrlist_t *src)
{
    ptrlist_t *dst = ptrlist_new();

    if (!src || src->list.len == 0) {
        return dst;
    }

    n00b_list_free(dst->list);
    dst->list = n00b_list_clone(src->list);

    return dst;
}

static inline void
ptrlist_free(ptrlist_t *l)
{
    if (l) {
        n00b_list_free(l->list);
        n00b_free(l);
    }
}

static inline void
ptrlist_extend(ptrlist_t *dst, ptrlist_t *src)
{
    if (!src || src->list.len == 0) {
        return;
    }

    n00b_list_insert_list(dst->list, dst->list.len, src->list);
}

// ============================================================================
// Tracking arrays for cleanup
// ============================================================================

static inline void
track_virt_item(n00b_earley_parser_t *p, void *ptr)
{
    if (!ptr) {
        return;
    }

    if (p->virt_items_len >= p->virt_items_cap) {
        int32_t new_cap = p->virt_items_cap ? p->virt_items_cap * 2 : 64;
        void  **new_buf = n00b_alloc_array(void *, new_cap);

        if (p->virt_items_len > 0) {
            memcpy(new_buf, p->virt_items,
                   (size_t)p->virt_items_len * sizeof(void *));
        }

        n00b_free(p->virt_items);
        p->virt_items     = new_buf;
        p->virt_items_cap = new_cap;
    }

    p->virt_items[p->virt_items_len++] = ptr;
}

static inline void
track_nb_info(n00b_earley_parser_t *p, void *ptr)
{
    if (!ptr) {
        return;
    }

    if (!p->tree_nb_infos.data) {
        p->tree_nb_infos = n00b_list_new_private(void *);
    }

    n00b_list_push(p->tree_nb_infos, ptr);
}

static inline void
track_ptrlist(n00b_earley_parser_t *p, ptrlist_t *pl)
{
    if (!pl) {
        return;
    }

    if (!p->tree_ptrlists.data) {
        p->tree_ptrlists = n00b_list_new_private(void *);
    }

    n00b_list_push(p->tree_ptrlists, pl);
}

// ============================================================================
// nb_info_t -- intermediate tree node during construction
// ============================================================================

typedef struct nb_info_t {
    n00b_nt_node_t     *pnode;
    n00b_token_info_t  *token;       // non-NULL for terminal nodes
    ptrlist_t          *opts;        // list of n00b_parse_tree_t*
    ptrlist_t          *slots;       // list of ptrlist_t* (per-child options)
    int                 num_kids;
    n00b_earley_item_t *bottom_item;
    n00b_earley_item_t *top_item;
    bool                cached;
    bool                visiting;
} nb_info_t;

static nb_info_t *populate_subtree(n00b_earley_parser_t *p,
                                   n00b_earley_item_t   *end);

// ============================================================================
// Parse node helpers
// ============================================================================

static inline n00b_nt_node_t *
new_epsilon_node(void)
{
    n00b_nt_node_t *pn = n00b_alloc(n00b_nt_node_t);

    pn->name = r"ε";
    pn->id   = N00B_EMPTY_STRING;

    return pn;
}

static inline n00b_nt_node_t *
copy_nt_node(n00b_nt_node_t *in)
{
    n00b_nt_node_t *out = n00b_alloc(n00b_nt_node_t);

    memcpy(out, in, sizeof(n00b_nt_node_t));

    return out;
}

// ============================================================================
// Hashset iteration helper -- collect items into a ptrlist
// ============================================================================

static ptrlist_t *
item_set_to_list(n00b_item_set_t *s)
{
    ptrlist_t *result = ptrlist_new();

    if (!s) {
        return result;
    }

    n00b_dict_foreach(s, k, v, {
        (void)v;
        ptrlist_push(result, k);
    });

    return result;
}

// ============================================================================
// Deterministic ordering of Earley item lists
// ============================================================================

// Compare two Earley items by stable, insertion-order-independent properties
// for deterministic iteration over completor item sets. Without this, dict
// iteration order depends on memory addresses, causing non-deterministic
// forest construction.
//
// We use the start item's (estate_id, ruleset_id, rule_index) plus the
// item's own (estate_id, cursor, penalty, cost) — all of which are
// determined by grammar structure and input, not by processing order.
// We avoid eitem_index since it depends on insertion order into the
// Earley state, which itself depends on dict iteration order.
static int
item_cmp(const void *a, const void *b)
{
    n00b_earley_item_t *ia = *(n00b_earley_item_t **)a;
    n00b_earley_item_t *ib = *(n00b_earley_item_t **)b;

    // Compare by start item's origin set.
    int32_t sa = ia->start_item ? ia->start_item->estate_id : -1;
    int32_t sb = ib->start_item ? ib->start_item->estate_id : -1;

    if (sa != sb) {
        return sa < sb ? -1 : 1;
    }

    // Compare by which NT / rule alternative.
    if (ia->ruleset_id != ib->ruleset_id) {
        return ia->ruleset_id < ib->ruleset_id ? -1 : 1;
    }

    if (ia->rule_index != ib->rule_index) {
        return ia->rule_index < ib->rule_index ? -1 : 1;
    }

    // Compare by end position.
    if (ia->estate_id != ib->estate_id) {
        return ia->estate_id < ib->estate_id ? -1 : 1;
    }

    // Compare by cursor position.
    if (ia->cursor != ib->cursor) {
        return ia->cursor < ib->cursor ? -1 : 1;
    }

    // Compare by penalty/cost as final tiebreaker.
    if (ia->penalty != ib->penalty) {
        return ia->penalty < ib->penalty ? -1 : 1;
    }

    if (ia->cost != ib->cost) {
        return ia->cost < ib->cost ? -1 : 1;
    }

    return 0;
}

// Sort a ptrlist of Earley items deterministically.
static void
sort_items(ptrlist_t *l)
{
    n00b_list_sort(l->list, item_cmp);
}

// ============================================================================
// Tree dedup via structural hashing
// ============================================================================

static uint64_t
parse_node_hash(n00b_parse_tree_t *t)
{
    // Simple FNV-1a style hash over structural data.
    uint64_t h = 0xcbf29ce484222325ULL;

#define MIX(val)                      \
    do {                              \
        uint64_t v = (uint64_t)(val); \
        h ^= v;                       \
        h *= 0x100000001b3ULL;        \
    } while (0)

    if (n00b_tree_is_leaf(t)) {
        n00b_token_info_t *tok = n00b_tree_leaf_value(t);

        MIX(1ULL << 33);

        if (tok) {
            MIX(tok->tid);
            MIX(((uint64_t)tok->tid << 32)
                | (uint64_t)(uint32_t)tok->index);

            if (n00b_option_is_set(tok->value)) {
                n00b_string_t *val = n00b_option_get(tok->value);

                for (size_t i = 0; i < val->u8_bytes; i++) {
                    MIX(val->data[i]);
                }
            }
        }
    }
    else {
        n00b_nt_node_t *pn = &n00b_tree_node_value(t);

        if (pn->hv) {
            return pn->hv;
        }

        MIX(pn->id);
        MIX(((uint64_t)pn->start << 32) | (uint64_t)(uint32_t)pn->end);
        MIX(((uint64_t)pn->penalty << 32) | (uint64_t)pn->cost);

        size_t nc = n00b_tree_num_children(t);

        MIX(nc);

        if (pn->name && pn->name->data) {
            for (size_t j = 0; j < pn->name->u8_bytes; j++) {
                MIX(pn->name->data[j]);
            }
        }

        for (size_t i = 0; i < nc; i++) {
            MIX(parse_node_hash(n00b_tree_child(t, i)));
        }

        pn->hv = h;
    }

#undef MIX

    return h;
}

static ptrlist_t *
clean_trees(ptrlist_t *l)
{
    size_t n = ptrlist_len(l);

    if (n < 2) {
        return l;
    }

    size_t     cap    = n * 4;
    uint64_t  *hashes = n00b_alloc_array(uint64_t, cap);
    ptrlist_t *result = ptrlist_new();

    for (size_t i = 0; i < n; i++) {
        n00b_parse_tree_t *t  = ptrlist_get(l, i);
        uint64_t           hv = parse_node_hash(t);
        size_t             ix = hv % cap;
        bool               dup = false;

        for (size_t j = 0; j < cap; j++) {
            size_t slot = (ix + j) % cap;

            if (hashes[slot] == 0) {
                hashes[slot] = hv;
                break;
            }

            if (hashes[slot] == hv) {
                dup = true;
                break;
            }
        }

        if (!dup) {
            ptrlist_push(result, t);
        }
    }

    n00b_free(hashes);
    ptrlist_free(l);

    return result;
}

// ============================================================================
// Deterministic tree sorting via grammar disambiguator
// ============================================================================

// Sort a ptrlist of parse trees using the grammar's disambiguator.
// Ensures deterministic forest ordering regardless of hash/iteration order.
static void
sort_trees(ptrlist_t *l, n00b_tree_disambig_fn_t cmp)
{
    size_t n = ptrlist_len(l);

    if (n < 2) {
        return;
    }

    // Simple insertion sort — forest sizes are typically very small.
    for (size_t i = 1; i < n; i++) {
        n00b_parse_tree_t *key = ptrlist_get(l, i);
        size_t             j   = i;

        while (j > 0 && cmp(ptrlist_get(l, j - 1), key) > 0) {
            l->list.data[j] = l->list.data[j - 1];
            j--;
        }

        l->list.data[j] = key;
    }
}

// ============================================================================
// Score filtering -- keep only lowest (penalty, cost) trees
// ============================================================================

static ptrlist_t *
score_filter(ptrlist_t *opts)
{
    size_t n = ptrlist_len(opts);

    if (n <= 1) {
        return opts;
    }

    uint32_t   penalty = ~0u;
    uint32_t   cost    = ~0u;
    ptrlist_t *results = ptrlist_new();

    for (size_t i = 0; i < n; i++) {
        n00b_parse_tree_t *t  = ptrlist_get(opts, i);
        n00b_nt_node_t    *pn = &n00b_tree_node_value(t);

        if (pn->penalty < penalty) {
            penalty = pn->penalty;
            cost    = pn->cost;
        }
        else if (pn->penalty == penalty && pn->cost < cost) {
            cost = pn->cost;
        }
    }

    for (size_t i = 0; i < n; i++) {
        n00b_parse_tree_t *t  = ptrlist_get(opts, i);
        n00b_nt_node_t    *pn = &n00b_tree_node_value(t);

        if (pn->penalty == penalty && pn->cost == cost) {
            ptrlist_push(results, t);
        }
    }

    ptrlist_free(opts);

    return results;
}

// ============================================================================
// Slot option management
// ============================================================================

static void
add_option(nb_info_t *parent, int i, nb_info_t *kid)
{
    while ((int)ptrlist_len(parent->slots) <= i) {
        ptrlist_push(parent->slots, NULL);
    }

    ptrlist_t *options = ptrlist_get(parent->slots, i);

    if (!options) {
        options = ptrlist_new();
        ptrlist_set(parent->slots, i, options);
    }

    ptrlist_push(options, kid);
}

// ============================================================================
// get_node -- create nb_info_t for an earley item pair (top, bottom)
// ============================================================================

static nb_info_t *
get_node(n00b_earley_parser_t *p, n00b_earley_item_t *b)
{
    n00b_earley_item_t *top = b->start_item;

    // Check cache on the start item.
    if (top->cache) {
        bool   found = false;
        void  *cached = n00b_dict_get(top->cache, b, &found);

        if (found && cached) {
            return (nb_info_t *)cached;
        }
    }

    n00b_nt_node_t *pn     = n00b_alloc(n00b_nt_node_t);
    nb_info_t      *result = n00b_alloc(nb_info_t);

    track_nb_info(p, result);
    result->pnode       = pn;
    result->bottom_item = b;
    result->top_item    = top;
    result->slots       = ptrlist_new();
    track_ptrlist(p, result->slots);

    pn->id         = top->ruleset_id;
    pn->rule_index = top->rule_index;
    pn->start      = top->estate_id;
    pn->end        = b->estate_id;
    pn->penalty    = b->penalty;
    pn->cost       = b->cost;

    // Create cache dict if needed.
    if (!top->cache) {
        top->cache = n00b_alloc(n00b_dict_t(n00b_earley_item_t *, void *));
        n00b_dict_init(top->cache,
                       .hash = n00b_hash_word,
                       .skip_obj_hash = true);
    }

    n00b_dict_put(top->cache, b, result);

    n00b_parse_rule_t *rule = top->rule;

    if (b->subtree_info == N00B_SI_GROUP_END) {
        pn->group_top = true;
        pn->id        = N00B_GROUP_ID;
    }
    else {
        result->num_kids = (int)n00b_list_len(rule->contents);

        if (top->group_top) {
            pn->group_item = true;
            pn->id         = N00B_GROUP_ID;
        }
    }

    // Pre-populate slots with NULLs.
    for (int i = 0; i < result->num_kids; i++) {
        ptrlist_push(result->slots, NULL);
    }

    // Name.
    n00b_nonterm_t *nt = n00b_get_nonterm(p->grammar, top->ruleset_id);

    if (pn->group_top) {
        // For group nodes, look up via contents_id (the actual group NT),
        // not ruleset_id (which is gid and collides with real NT ids).
        n00b_nonterm_t *gnt = (top->group)
            ? n00b_get_nonterm(p->grammar, top->group->contents_id)
            : NULL;
        pn->name = gnt ? gnt->name : r"group";
    }
    else if (pn->group_item) {
        if (top->group_top && top->group_top->group) {
            n00b_nonterm_t *gnt
                = n00b_get_nonterm(p->grammar,
                                    top->group_top->group->contents_id);
            pn->name = gnt ? gnt->name : r"group-item";
        }
        else {
            pn->name = nt ? nt->name : r"?";
        }
    }
    else {
        pn->name = nt ? nt->name : r"?";
    }

    if (rule->penalty_rule) {
        pn->penalty = b->penalty;
    }

    return result;
}

// ============================================================================
// add_token_node / add_epsilon_node
// ============================================================================

static void
add_token_node(n00b_earley_parser_t *p, nb_info_t *node,
               n00b_earley_item_t *ei)
{
    nb_info_t *ni = n00b_alloc(nb_info_t);

    track_nb_info(p, ni);

    n00b_earley_state_t *s = p->states.data[ei->estate_id];

    ni->top_item    = ei;
    ni->bottom_item = ei;
    ni->token       = s->token;

    add_option(node, ei->cursor, ni);
}

static void
add_epsilon_node(n00b_earley_parser_t *p, nb_info_t *node,
                 n00b_earley_item_t *ei)
{
    nb_info_t      *ni = n00b_alloc(nb_info_t);
    n00b_nt_node_t *pn = new_epsilon_node();

    track_nb_info(p, ni);

    pn->start       = ei->estate_id;
    pn->end         = ei->estate_id;
    ni->top_item    = ei;
    ni->bottom_item = ei;
    ni->pnode       = pn;

    add_option(node, ei->cursor, ni);
}

// ============================================================================
// scan_rule_items -- walk backward through a rule's earley items
// ============================================================================

static void
scan_rule_items(n00b_earley_parser_t *p, nb_info_t *parent_ni,
                n00b_earley_item_t *end)
{
    n00b_earley_item_t *start = end->start_item;
    n00b_earley_item_t *cur   = end;
    n00b_earley_item_t *prev  = end;

    size_t rule_len = n00b_list_len(start->rule->contents);

    for (size_t i = 0; i < rule_len; i++) {
        cur = cur->previous_scan;

        if (!cur) {
            break;
        }

        int cursor = cur->cursor;

        n00b_match_t *pi = &start->rule->contents.data[cur->cursor];

        switch (pi->kind) {
        case N00B_MATCH_EMPTY:
            add_epsilon_node(p, parent_ni, cur);
            break;

        case N00B_MATCH_TERMINAL:
        case N00B_MATCH_ANY:
        case N00B_MATCH_CLASS:
        case N00B_MATCH_SET:
            add_token_node(p, parent_ni, cur);
            break;

        case N00B_MATCH_NT:
        case N00B_MATCH_GROUP:
        default: {
            ptrlist_t *bottoms   = item_set_to_list(prev->completors);
            sort_items(bottoms);
            size_t     n_bottoms = ptrlist_len(bottoms);

            for (size_t j = 0; j < n_bottoms; j++) {
                n00b_earley_item_t *send    = ptrlist_get(bottoms, j);
                nb_info_t          *subnode = populate_subtree(p, send);

                add_option(parent_ni, cursor, subnode);
            }

            ptrlist_free(bottoms);
            break;
        }
        }

        prev = cur;
    }
}

// ============================================================================
// scan_group_items -- populate group children from completor chains
// ============================================================================

static void
scan_group_items(n00b_earley_parser_t *p, nb_info_t *group_ni,
                 n00b_earley_item_t *end)
{
    ptrlist_t *clist  = item_set_to_list(end->completors);
    sort_items(clist);
    size_t     n      = ptrlist_len(clist);
    uint32_t   minp   = ~0u;
    uint32_t   nitems = ~0u;

    for (size_t i = 0; i < n; i++) {
        n00b_earley_item_t *cur = ptrlist_get(clist, i);

        if (cur->penalty < minp) {
            minp   = cur->penalty;
            nitems = (uint32_t)cur->match_ct;
        }

        if (cur->penalty == minp && (uint32_t)cur->match_ct < nitems) {
            nitems = (uint32_t)cur->match_ct;
        }
    }

    for (size_t i = 0; i < n; i++) {
        n00b_earley_item_t *cur = ptrlist_get(clist, i);

        if (cur->penalty != minp || (uint32_t)cur->match_ct != nitems) {
            continue;
        }

        int ix             = cur->match_ct;
        group_ni->num_kids = cur->match_ct;

        while (cur && ix-- > 0) {
            nb_info_t          *possible_node = populate_subtree(p, cur);
            n00b_earley_item_t *gstart        = cur->start_item;

            add_option(group_ni, ix, possible_node);
            cur = gstart->previous_scan;
        }

        break;
    }

    ptrlist_free(clist);
}

// ============================================================================
// Leo chain expansion for tree building
// ============================================================================

static nb_info_t *
expand_leo_chain(n00b_earley_parser_t *p, n00b_earley_item_t *leo_end)
{
    n00b_earley_item_t *direct = leo_end->leo_direct_parent;

    if (!direct) {
        nb_info_t *ni = get_node(p, leo_end);

        if (!ni->cached && !ni->visiting) {
            ni->visiting = true;
            scan_rule_items(p, ni, leo_end);
            ni->cached   = true;
            ni->visiting = false;
        }

        return ni;
    }

    // Walk prediction chain from direct parent upward to topmost.
    ptrlist_t          *chain      = ptrlist_new();
    n00b_earley_item_t *cur_parent = direct;
    n00b_earley_item_t *topmost    = leo_end->previous_scan;

    while (cur_parent) {
        ptrlist_push(chain, cur_parent);

        if (cur_parent == topmost) {
            break;
        }

        n00b_item_set_t *ps = cur_parent->start_item->parent_states;

        if (!ps || ps->length != 1) {
            break;
        }

        n00b_earley_item_t *next = NULL;

        n00b_dict_foreach(ps, k, v, {
            (void)v;
            next = k;
            break;
        });

        cur_parent = next;
    }

    // Extract inner completing item.
    n00b_earley_item_t *inner_completor = NULL;
    n00b_item_set_t    *inner_set       = leo_end->completors;

    if (inner_set) {
        n00b_dict_foreach(inner_set, k, v, {
            (void)v;
            inner_completor = k;
            break;
        });
    }

    // Build inside-out.
    size_t n_levels = ptrlist_len(chain);

    for (size_t i = 0; i < n_levels; i++) {
        n00b_earley_item_t *parent = ptrlist_get(chain, i);

        n00b_earley_item_t *virt = n00b_alloc(n00b_earley_item_t);

        track_virt_item(p, virt);
        virt->start_item    = parent->start_item;
        virt->cursor        = parent->cursor + 1;
        virt->previous_scan = parent;
        virt->rule          = parent->start_item->rule;
        virt->estate_id     = leo_end->estate_id;
        virt->penalty       = leo_end->penalty;
        virt->cost          = leo_end->cost;
        virt->op            = N00B_EO_COMPLETE_N;
        virt->subtree_info  = N00B_SI_NT_RULE_END;

        virt->completors = n00b_item_set_new();

        if (inner_completor) {
            n00b_item_set_put(virt->completors, inner_completor);
        }

        nb_info_t *ni = get_node(p, virt);

        if (!ni->cached && !ni->visiting) {
            ni->visiting = true;
            scan_rule_items(p, ni, virt);
            ni->cached   = true;
            ni->visiting = false;
        }

        inner_completor = virt;
    }

    ptrlist_free(chain);

    if (inner_completor) {
        return get_node(p, inner_completor);
    }

    return get_node(p, leo_end);
}

// ============================================================================
// populate_subtree -- recursive memoized tree population
// ============================================================================

static nb_info_t *
populate_subtree(n00b_earley_parser_t *p, n00b_earley_item_t *end)
{
    if (end->leo_item) {
        return expand_leo_chain(p, end);
    }

    nb_info_t *ni = get_node(p, end);

    if (ni->cached) {
        return ni;
    }

    if (ni->visiting) {
        return ni;
    }

    ni->visiting = true;

    if (end->subtree_info == N00B_SI_GROUP_END) {
        scan_group_items(p, ni, end);
    }
    else {
        scan_rule_items(p, ni, end);
    }

    ni->cached   = true;
    ni->visiting = false;

    return ni;
}

// ============================================================================
// search_for_end_items -- find completions of the start symbol
// ============================================================================

static ptrlist_t *
search_for_end_items(n00b_earley_parser_t *p)
{
    n00b_earley_state_t *state   = p->current_state;
    ptrlist_t           *results = ptrlist_new();
    size_t               n       = n00b_list_len(state->items);

    if (!n) {
        return results;
    }

    while (n-- > 0) {
        n00b_earley_item_t *ei  = state->items.data[n];
        n00b_earley_item_t *top = ei->start_item;

        if (top->subtree_info != N00B_SI_NT_RULE_START) {
            continue;
        }

        if (top->ruleset_id != p->start) {
            continue;
        }

        if (ei->cursor != (int32_t)n00b_list_len(top->rule->contents)) {
            continue;
        }

        ptrlist_push(results, ei);
    }

    return results;
}

// ============================================================================
// Post-processing: convert nb_info_t into actual tree nodes
// ============================================================================

static ptrlist_t *postprocess_subtree(n00b_earley_parser_t *p, nb_info_t *ni);

static inline ptrlist_t *
process_slot(n00b_earley_parser_t *p, ptrlist_t *ni_options)
{
    ptrlist_t *result = ptrlist_new();
    size_t     n      = ptrlist_len(ni_options);

    for (size_t i = 0; i < n; i++) {
        nb_info_t *sub      = ptrlist_get(ni_options, i);
        ptrlist_t *sub_opts = postprocess_subtree(p, sub);

        ptrlist_extend(result, sub_opts);

        if (sub_opts != sub->opts) {
            ptrlist_free(sub_opts);
        }
    }

    return result;
}

static inline ptrlist_t *
package_single_slot_options(n00b_earley_parser_t *p, nb_info_t *ni,
                            ptrlist_t *t_opts)
{
    ptrlist_t *output_opts = ptrlist_new();
    size_t     n           = ptrlist_len(t_opts);

    for (size_t i = 0; i < n; i++) {
        n00b_parse_tree_t *kid_t = ptrlist_get(t_opts, i);
        n00b_nt_node_t    *pn    = copy_nt_node(ni->pnode);
        n00b_parse_tree_t *t     = n00b_tree_node(n00b_nt_node_t,
                                                    n00b_token_info_t *, *pn);

        n00b_free(pn);

        if (!n00b_tree_is_leaf(kid_t)) {
            n00b_nt_node_t *kid_pn = &n00b_tree_node_value(kid_t);

            if (kid_pn->penalty > n00b_tree_node_value(t).penalty) {
                n00b_tree_node_value(t).penalty = kid_pn->penalty;
            }
        }

        (void)n00b_tree_add_child(t, kid_t);

        ptrlist_push(output_opts, t);
    }

    ni->opts = output_opts;

    ptrlist_t *filtered = score_filter(clean_trees(output_opts));

    sort_trees(filtered, n00b_get_disambiguator(p->grammar));

    return filtered;
}

// Get the start token position of a tree node (leaf or NT).
static inline int32_t
tree_node_start(n00b_parse_tree_t *t)
{
    if (n00b_tree_is_leaf(t)) {
        n00b_token_info_t *tok = n00b_tree_leaf_value(t);
        return tok ? tok->index : 0;
    }
    return n00b_tree_node_value(t).start;
}

// Get the end token position of a tree node (leaf or NT).
static inline int32_t
tree_node_end(n00b_parse_tree_t *t)
{
    if (n00b_tree_is_leaf(t)) {
        n00b_token_info_t *tok = n00b_tree_leaf_value(t);
        return tok ? tok->index + 1 : 0;
    }
    return n00b_tree_node_value(t).end;
}

// Get the penalty of a tree node (0 for leaves).
static inline uint32_t
tree_node_penalty(n00b_parse_tree_t *t)
{
    if (n00b_tree_is_leaf(t)) {
        return 0;
    }
    return n00b_tree_node_value(t).penalty;
}

static inline ptrlist_t *
parse_node_zipper(ptrlist_t *kid_sets, ptrlist_t *options)
{
    size_t n              = ptrlist_len(options);
    size_t num_start_sets = ptrlist_len(kid_sets);

    if (n == 1) {
        n00b_parse_tree_t *t = ptrlist_get(options, 0);

        for (size_t i = 0; i < num_start_sets; i++) {
            ptrlist_t *kid_set = ptrlist_get(kid_sets, i);

            ptrlist_push(kid_set, t);
        }

        return kid_sets;
    }

    ptrlist_t *results = ptrlist_new();

    for (size_t i = 0; i < n; i++) {
        n00b_parse_tree_t *option_t  = ptrlist_get(options, i);
        int32_t            opt_start = tree_node_start(option_t);

        for (size_t j = 0; j < num_start_sets; j++) {
            ptrlist_t         *s1     = ptrlist_get(kid_sets, j);
            size_t             slen   = ptrlist_len(s1);
            n00b_parse_tree_t *prev_t = ptrlist_get(s1, slen - 1);

            if (!prev_t) {
                continue;
            }

            if (tree_node_end(prev_t) != opt_start) {
                continue;
            }

            ptrlist_t *new_set = ptrlist_copy(s1);

            ptrlist_push(new_set, option_t);
            ptrlist_push(results, new_set);
        }
    }

    return results;
}

static inline void
package_kid_sets(n00b_earley_parser_t *p, nb_info_t *ni,
                 ptrlist_t *kid_sets)
{
    size_t n_sets = ptrlist_len(kid_sets);

    ni->opts = ptrlist_new();

    for (size_t i = 0; i < n_sets; i++) {
        ptrlist_t      *a_set       = ptrlist_get(kid_sets, i);
        n00b_nt_node_t *copy        = copy_nt_node(ni->pnode);
        n00b_parse_tree_t *t        = n00b_tree_node(n00b_nt_node_t,
                                                      n00b_token_info_t *, *copy);
        uint32_t        old_penalty = copy->penalty;

        n00b_free(copy);

        n00b_nt_node_t *tpn = &n00b_tree_node_value(t);

        tpn->penalty = 0;

        for (int j = 0; j < ni->num_kids; j++) {
            n00b_parse_tree_t *kid_t = ptrlist_get(a_set, j);

            if (!kid_t) {
                continue;
            }

            tpn->penalty += tree_node_penalty(kid_t);

            (void)n00b_tree_add_child(t, kid_t);
        }

        if (tpn->penalty < old_penalty) {
            tpn->penalty = old_penalty;
        }


        ptrlist_push(ni->opts, t);
    }

    ni->opts = score_filter(clean_trees(ni->opts));
    sort_trees(ni->opts, n00b_get_disambiguator(p->grammar));
}

static ptrlist_t *
postprocess_subtree(n00b_earley_parser_t *p, nb_info_t *ni)
{
    if (ni->opts) {
        return ni->opts;
    }

    if (ni->visiting) {
        return ptrlist_new();
    }

    ni->visiting = true;

    // Leaf nodes (tokens and epsilon).
    if (!ni->num_kids) {
        ni->opts = ptrlist_new();

        n00b_parse_tree_t *t;

        if (ni->token) {
            // Terminal — create a tree leaf.
            t = n00b_tree_leaf(n00b_nt_node_t, n00b_token_info_t *, ni->token);
        }
        else {
            // Epsilon or other NT node with no children.
            t = n00b_tree_node(n00b_nt_node_t, n00b_token_info_t *, *ni->pnode);
        }

        ptrlist_push(ni->opts, t);

        return ni->opts;
    }

    // Process first slot.
    ptrlist_t *slot_options = process_slot(p, ptrlist_get(ni->slots, 0));

    // Single child.
    if (ni->num_kids == 1) {
        ptrlist_t *result = package_single_slot_options(p, ni, slot_options);

        ptrlist_free(slot_options);
        ni->visiting = false;

        return result;
    }

    // Multiple children -- zipper.
    ptrlist_t *kid_sets = ptrlist_new();
    size_t     n        = ptrlist_len(slot_options);

    for (size_t i = 0; i < n; i++) {
        n00b_parse_tree_t *t     = ptrlist_get(slot_options, i);
        ptrlist_t         *klist = ptrlist_new();

        ptrlist_push(klist, t);
        ptrlist_push(kid_sets, klist);
    }

    ptrlist_free(slot_options);

    for (int i = 1; i < ni->num_kids; i++) {
        ptrlist_t *next_options = process_slot(p, ptrlist_get(ni->slots, i));
        ptrlist_t *new_kid_sets = parse_node_zipper(kid_sets, next_options);

        if (new_kid_sets != kid_sets) {
            ptrlist_free(kid_sets);
        }

        ptrlist_free(next_options);
        kid_sets = new_kid_sets;
    }

    package_kid_sets(p, ni, kid_sets);

    for (size_t i = 0; i < ptrlist_len(kid_sets); i++) {
        ptrlist_free(ptrlist_get(kid_sets, i));
    }

    ptrlist_free(kid_sets);

    ni->visiting = false;

    return ni->opts;
}

// ============================================================================
// Build forest -- main entry using item chains
// ============================================================================

static ptrlist_t *
build_forest(n00b_earley_parser_t *p)
{
    ptrlist_t *results = ptrlist_new();
    ptrlist_t *roots   = ptrlist_new();
    ptrlist_t *ends    = search_for_end_items(p);
    size_t     n       = ptrlist_len(ends);

    p->grammar->suspend_penalty_hiding++;

    for (size_t i = 0; i < n; i++) {
        n00b_earley_item_t *end = ptrlist_get(ends, i);

        if (end->start_item->estate_id != 0) {
            continue;
        }

        nb_info_t *res = populate_subtree(p, end);

        if (!res) {
            continue;
        }

        ptrlist_push(roots, res);
    }

    n = ptrlist_len(roots);

    for (size_t i = 0; i < n; i++) {
        nb_info_t *ni        = ptrlist_get(roots, i);
        ptrlist_t *possibles = postprocess_subtree(p, ni);

        ptrlist_extend(results, possibles);
    }

    p->grammar->suspend_penalty_hiding--;

    ptrlist_free(ends);
    ptrlist_free(roots);

    return results;
}

// ============================================================================
// BSR-based tree reconstruction
// ============================================================================

typedef struct {
    int32_t left;
    int32_t pivot;
} bsr_pair_t;

typedef n00b_list_t(bsr_pair_t) bsr_pair_list_t;
typedef bsr_pair_list_t *bsr_pair_list_ptr_t;
typedef n00b_dict_t(uint64_t, bsr_pair_list_ptr_t) bsr_index_t;

static void
bsr_index_init(bsr_index_t *idx)
{
    n00b_dict_init(idx, .hash = n00b_hash_word, .skip_obj_hash = true);
}

static void
bsr_index_free(bsr_index_t *idx)
{
    n00b_dict_foreach(idx, k, v, {
        (void)k;
        if (v) {
            n00b_list_free(*v);
            n00b_free(v);
        }
    });
}

static bsr_pair_list_t *
bsr_index_find(bsr_index_t *idx, uint64_t key)
{
    bool                 found = false;
    bsr_pair_list_ptr_t  val   = n00b_dict_get(idx, key, &found);

    return found ? val : NULL;
}

static void
bsr_index_insert(bsr_index_t *idx, int32_t slot, int32_t right,
                 int32_t left, int32_t pivot)
{
    uint64_t key = ((uint64_t)(uint32_t)slot << 32) | (uint64_t)(uint32_t)right;

    bool                found    = false;
    bsr_pair_list_ptr_t existing = n00b_dict_get(idx, key, &found);

    if (found && existing) {
        n00b_list_push(*existing, ((bsr_pair_t){ left, pivot }));
    }
    else {
        bsr_pair_list_ptr_t new_list = n00b_alloc(bsr_pair_list_t);
        *new_list = n00b_list_new_private(bsr_pair_t);
        n00b_list_push(*new_list, ((bsr_pair_t){ left, pivot }));
        n00b_dict_put(idx, key, new_list);
    }
}

static void
bsr_build_index(n00b_earley_parser_t *p, bsr_index_t *idx)
{
    bsr_index_init(idx);

    for (int32_t i = 0; i < p->bsr_count; i++) {
        n00b_bsr_element_t *e = &p->bsr_set[i];

        bsr_index_insert(idx, e->slot, e->right_extent,
                         e->left_extent, e->pivot);
    }
}

// BSR memoization: maps packed (nt_id, left, right) → ptrlist_t*.
// A NULL value after n00b_dict_contains() == true means "in-progress" (cycle).
// A non-NULL value is the cached tree list.

typedef ptrlist_t *ptrlist_ptr_t;
typedef n00b_dict_t(uint64_t, ptrlist_ptr_t) bsr_memo_t;

static void
bsr_memo_init(bsr_memo_t *m)
{
    n00b_dict_init(m, .hash = n00b_hash_word, .skip_obj_hash = true);
}

static uint64_t
bsr_memo_key(int64_t nt_id, int32_t left, int32_t right)
{
    uint64_t k = ((uint64_t)(uint32_t)nt_id * 2654435761ULL)
               ^ ((uint64_t)(uint32_t)left * 40499ULL)
               ^ ((uint64_t)(uint32_t)right);
    k = (k ^ (k >> 16)) * 0x45d9f3b;
    return k;
}

// Returns: -1 if not found, 0 if in-progress (cycle), 1 if result is ready.
// When returning 1, *out is set to the cached result.
static int
bsr_memo_find(bsr_memo_t *m, int64_t nt_id, int32_t left, int32_t right,
              ptrlist_t **out)
{
    uint64_t key = bsr_memo_key(nt_id, left, right);

    if (!n00b_dict_contains(m, key)) {
        return -1;
    }

    bool        found = false;
    ptrlist_ptr_t val = n00b_dict_get(m, key, &found);

    if (found && val) {
        *out = val;
        return 1;
    }

    return 0; // in-progress
}

// Insert an in-progress marker.
static void
bsr_memo_mark_in_progress(bsr_memo_t *m, int64_t nt_id,
                           int32_t left, int32_t right)
{
    uint64_t      key     = bsr_memo_key(nt_id, left, right);
    ptrlist_ptr_t nullval = NULL;
    n00b_dict_put(m, key, nullval);
}

// Store the completed result.
static void
bsr_memo_store(bsr_memo_t *m, int64_t nt_id, int32_t left, int32_t right,
               ptrlist_t *result)
{
    uint64_t key = bsr_memo_key(nt_id, left, right);
    n00b_dict_put(m, key, result);
}


typedef struct {
    n00b_earley_parser_t *parser;
    bsr_index_t           index;
    bsr_memo_t            memo;
} bsr_ctx_t;

// Forward declarations.
static ptrlist_t *bsr_build_nt(bsr_ctx_t *ctx, int64_t nt_id,
                               int32_t left, int32_t right);
static ptrlist_t *bsr_build_rule(bsr_ctx_t *ctx, int32_t rule_ix,
                                 int32_t left, int32_t right);
static ptrlist_t *bsr_build_prefix(bsr_ctx_t *ctx, int32_t rule_ix,
                                   int32_t left, int32_t right, int32_t k);
static ptrlist_t *bsr_build_symbol(bsr_ctx_t *ctx, n00b_match_t *match,
                                   int32_t left, int32_t right);
static ptrlist_t *bsr_build_group(bsr_ctx_t *ctx, n00b_rule_group_t *grp,
                                  int32_t left, int32_t right);

static int32_t
bsr_local_rule_index(n00b_grammar_t *g, n00b_nt_id_t nt_id,
                     int32_t global_rule_ix)
{
    n00b_nonterm_t *nt = n00b_get_nonterm(g, nt_id);

    if (!nt) {
        return 0;
    }

    size_t n = n00b_list_len(nt->rule_ids);

    for (size_t i = 0; i < n; i++) {
        if (nt->rule_ids.data[i] == global_rule_ix) {
            return (int32_t)i;
        }
    }

    return 0;
}

static n00b_earley_item_t *
bsr_find_completed_item(n00b_earley_parser_t *p, int32_t rule_ix,
                        int32_t start_set, int32_t end_set)
{
    n00b_earley_state_t *state = p->states.data[end_set];
    size_t               n     = n00b_list_len(state->items);
    n00b_parse_rule_t   *rule  = n00b_get_rule(p->grammar, rule_ix);

    if (!rule) {
        return NULL;
    }

    int32_t expected_cursor = (int32_t)n00b_list_len(rule->contents);

    for (size_t i = 0; i < n; i++) {
        n00b_earley_item_t *ei  = state->items.data[i];
        n00b_earley_item_t *top = ei->start_item;

        if (top->estate_id != start_set) {
            continue;
        }

        if (ei->rule != rule) {
            continue;
        }

        if (ei->cursor != expected_cursor) {
            continue;
        }

        return ei;
    }

    return NULL;
}

static n00b_parse_tree_t *
bsr_make_token_node(n00b_earley_parser_t *p, int32_t pos)
{
    n00b_earley_state_t *s = p->states.data[pos];

    return n00b_tree_leaf(n00b_nt_node_t, n00b_token_info_t *, s->token);
}

static ptrlist_t *
bsr_build_nt(bsr_ctx_t *ctx, int64_t nt_id, int32_t left, int32_t right)
{
    // Memoization: check if already computed or in-progress (cycle).
    ptrlist_t *cached = NULL;
    int        status = bsr_memo_find(&ctx->memo, nt_id, left, right, &cached);

    if (status == 1) {
        // Already computed — return a copy of the cached result.
        ptrlist_t *copy = ptrlist_new();
        ptrlist_extend(copy, cached);
        return copy;
    }

    if (status == 0) {
        // In-progress (cycle detected) — return empty to break recursion.
        return ptrlist_new();
    }

    // Insert in-progress marker.
    bsr_memo_mark_in_progress(&ctx->memo, nt_id, left, right);

    ptrlist_t      *results = ptrlist_new();
    n00b_nonterm_t *nt      = n00b_get_nonterm(ctx->parser->grammar, nt_id);

    if (!nt) {
        bsr_memo_store(&ctx->memo, nt_id, left, right, results);
        return results;
    }

    size_t n_rules = n00b_list_len(nt->rule_ids);

    for (size_t i = 0; i < n_rules; i++) {
        int32_t    rule_ix = nt->rule_ids.data[i];
        ptrlist_t *trees   = bsr_build_rule(ctx, rule_ix, left, right);

        ptrlist_extend(results, trees);
        ptrlist_free(trees);
    }

    // Cache the result.
    bsr_memo_store(&ctx->memo, nt_id, left, right, results);

    return results;
}

static ptrlist_t *
bsr_build_rule(bsr_ctx_t *ctx, int32_t rule_ix,
               int32_t left, int32_t right)
{
    ptrlist_t         *results = ptrlist_new();
    n00b_grammar_t    *g       = ctx->parser->grammar;
    n00b_parse_rule_t *rule    = n00b_get_rule(g, rule_ix);

    if (!rule) {
        return results;
    }

    int32_t rule_len = (int32_t)n00b_list_len(rule->contents);

    n00b_nonterm_t *rule_nt = n00b_get_nonterm(g, rule->nt_id);

    // Epsilon rule.
    if (rule_len == 0) {
        if (left == right) {
            n00b_nt_node_t pn = {0};

            pn.id         = rule->nt_id;
            pn.rule_index = bsr_local_rule_index(g, rule->nt_id, rule_ix);
            pn.start      = left;
            pn.end        = right;
            pn.name       = rule_nt ? rule_nt->name : r"?";

            n00b_parse_tree_t *t = n00b_tree_node(n00b_nt_node_t,
                                                    n00b_token_info_t *, pn);

            n00b_nt_node_t eps = {0};

            eps.name  = r"ε";
            eps.id    = N00B_EMPTY_STRING;
            eps.start = left;
            eps.end   = left;

            n00b_parse_tree_t *eps_t = n00b_tree_node(n00b_nt_node_t,
                                                        n00b_token_info_t *,
                                                        eps);

            (void)n00b_tree_add_child(t, eps_t);

            ptrlist_push(results, t);
        }

        return results;
    }

    // Single-symbol rule.
    if (rule_len == 1) {
        int32_t      slot = g->lr0_rule_item_base[rule_ix] + 1;
        uint64_t     key  = ((uint64_t)(uint32_t)slot << 32)
                          | (uint64_t)(uint32_t)right;
        bsr_pair_list_t *b   = bsr_index_find(&ctx->index, key);

        if (!b) {
            return results;
        }

        for (size_t i = 0; i < b->len; i++) {
            if (b->data[i].left != left) {
                continue;
            }

            int32_t    pivot = b->data[i].pivot;
            n00b_match_t *match = &rule->contents.data[0];
            ptrlist_t  *sub   = bsr_build_symbol(ctx, match, pivot, right);
            size_t      n_sub = ptrlist_len(sub);

            for (size_t j = 0; j < n_sub; j++) {
                n00b_parse_tree_t *child_t = ptrlist_get(sub, j);

                n00b_nt_node_t pn = {0};

                pn.id         = rule->nt_id;
                pn.rule_index = bsr_local_rule_index(g, rule->nt_id, rule_ix);
                pn.start      = left;
                pn.end        = right;
                pn.name       = rule_nt ? rule_nt->name : r"?";

                n00b_earley_item_t *ei
                    = bsr_find_completed_item(ctx->parser, rule_ix,
                                              left, right);

                if (ei) {
                    pn.penalty = ei->penalty;
                    pn.cost    = ei->cost;
                }

                if (rule_nt && rule_nt->group_nt) {
                    n00b_earley_item_t *top = ei ? ei->start_item : NULL;

                    if (top && top->group_top) {
                        pn.group_item = true;
                        pn.id         = N00B_GROUP_ID;
                    }
                }

                if (rule->penalty_rule) {
                    pn.penalty = ei ? ei->penalty : 0;
                }

                n00b_parse_tree_t *t = n00b_tree_node(
                    n00b_nt_node_t, n00b_token_info_t *, pn);

                (void)n00b_tree_add_child(t, child_t);

                uint32_t child_penalty = tree_node_penalty(child_t);

                if (child_penalty > n00b_tree_node_value(t).penalty) {
                    n00b_tree_node_value(t).penalty = child_penalty;
                }


                ptrlist_push(results, t);
            }

            ptrlist_free(sub);
        }

        return results;
    }

    // Multi-symbol rule.
    int32_t      complete_slot = g->lr0_rule_item_base[rule_ix] + rule_len;
    uint64_t     key           = ((uint64_t)(uint32_t)complete_slot << 32)
                               | (uint64_t)(uint32_t)right;
    bsr_pair_list_t *b            = bsr_index_find(&ctx->index, key);

    if (!b) {
        return results;
    }

    for (size_t i = 0; i < b->len; i++) {
        if (b->data[i].left != left) {
            continue;
        }

        int32_t pivot = b->data[i].pivot;

        n00b_match_t *last_match = &rule->contents.data[rule_len - 1];
        ptrlist_t    *right_opts = bsr_build_symbol(ctx, last_match,
                                                     pivot, right);

        ptrlist_t *prefix_opts = bsr_build_prefix(ctx, rule_ix, left,
                                                   pivot, rule_len - 1);

        size_t n_prefix = ptrlist_len(prefix_opts);
        size_t n_right  = ptrlist_len(right_opts);

        for (size_t pi = 0; pi < n_prefix; pi++) {
            ptrlist_t *prefix_kids = ptrlist_get(prefix_opts, pi);

            for (size_t ri = 0; ri < n_right; ri++) {
                n00b_parse_tree_t *right_child = ptrlist_get(right_opts, ri);

                n00b_nt_node_t pn = {0};

                pn.id         = rule->nt_id;
                pn.rule_index = bsr_local_rule_index(g, rule->nt_id, rule_ix);
                pn.start      = left;
                pn.end        = right;
                pn.name       = rule_nt ? rule_nt->name : r"?";

                n00b_earley_item_t *ei
                    = bsr_find_completed_item(ctx->parser, rule_ix,
                                              left, right);

                if (ei) {
                    pn.penalty = ei->penalty;
                    pn.cost    = ei->cost;
                }

                if (rule_nt && rule_nt->group_nt) {
                    n00b_earley_item_t *top = ei ? ei->start_item : NULL;

                    if (top && top->group_top) {
                        pn.group_item = true;
                        pn.id         = N00B_GROUP_ID;
                    }
                }

                if (rule->penalty_rule) {
                    pn.penalty = ei ? ei->penalty : 0;
                }

                n00b_parse_tree_t *t = n00b_tree_node(
                    n00b_nt_node_t, n00b_token_info_t *, pn);

                n00b_nt_node_t *tpn = &n00b_tree_node_value(t);

                uint32_t max_child_penalty = 0;

                for (size_t k = 0; k < ptrlist_len(prefix_kids); k++) {
                    n00b_parse_tree_t *kid     = ptrlist_get(prefix_kids, k);
                    uint32_t           kpenalty = tree_node_penalty(kid);

                    if (kpenalty > max_child_penalty) {
                        max_child_penalty = kpenalty;
                    }

                    (void)n00b_tree_add_child(t, kid);
                }

                uint32_t rpenalty = tree_node_penalty(right_child);

                if (rpenalty > max_child_penalty) {
                    max_child_penalty = rpenalty;
                }

                (void)n00b_tree_add_child(t, right_child);

                if (max_child_penalty > tpn->penalty) {
                    tpn->penalty = max_child_penalty;
                }


                ptrlist_push(results, t);
            }
        }

        for (size_t pi = 0; pi < n_prefix; pi++) {
            ptrlist_free(ptrlist_get(prefix_opts, pi));
        }

        ptrlist_free(prefix_opts);
        ptrlist_free(right_opts);
    }

    return results;
}

static ptrlist_t *
bsr_build_prefix(bsr_ctx_t *ctx, int32_t rule_ix,
                 int32_t left, int32_t right, int32_t k)
{
    ptrlist_t         *results = ptrlist_new();
    n00b_grammar_t    *g       = ctx->parser->grammar;
    n00b_parse_rule_t *rule    = n00b_get_rule(g, rule_ix);

    if (!rule || k <= 0) {
        return results;
    }

    if (k == 1) {
        n00b_match_t *match = &rule->contents.data[0];
        ptrlist_t    *opts  = bsr_build_symbol(ctx, match, left, right);
        size_t        n     = ptrlist_len(opts);

        for (size_t i = 0; i < n; i++) {
            n00b_parse_tree_t *t    = ptrlist_get(opts, i);
            ptrlist_t         *kids = ptrlist_new();

            ptrlist_push(kids, t);
            ptrlist_push(results, kids);
        }

        ptrlist_free(opts);

        return results;
    }

    int32_t      slot = g->lr0_rule_item_base[rule_ix] + k;
    uint64_t     key  = ((uint64_t)(uint32_t)slot << 32)
                      | (uint64_t)(uint32_t)right;
    bsr_pair_list_t *b   = bsr_index_find(&ctx->index, key);

    if (!b) {
        return results;
    }

    for (size_t i = 0; i < b->len; i++) {
        if (b->data[i].left != left) {
            continue;
        }

        int32_t pivot = b->data[i].pivot;

        n00b_match_t *match     = &rule->contents.data[k - 1];
        ptrlist_t    *sym_opts  = bsr_build_symbol(ctx, match, pivot, right);

        ptrlist_t *sub_prefix = bsr_build_prefix(ctx, rule_ix, left,
                                                  pivot, k - 1);

        size_t n_sub = ptrlist_len(sub_prefix);
        size_t n_sym = ptrlist_len(sym_opts);

        for (size_t si = 0; si < n_sub; si++) {
            ptrlist_t *sub_kids = ptrlist_get(sub_prefix, si);

            for (size_t sj = 0; sj < n_sym; sj++) {
                n00b_parse_tree_t *sym_t = ptrlist_get(sym_opts, sj);

                if (n_sub == 1 && n_sym == 1) {
                    ptrlist_push(sub_kids, sym_t);
                    ptrlist_push(results, sub_kids);
                }
                else {
                    ptrlist_t *new_kids = ptrlist_copy(sub_kids);

                    ptrlist_push(new_kids, sym_t);
                    ptrlist_push(results, new_kids);
                }
            }
        }

        if (n_sub > 1 || n_sym > 1) {
            for (size_t si = 0; si < n_sub; si++) {
                ptrlist_free(ptrlist_get(sub_prefix, si));
            }
        }

        ptrlist_free(sub_prefix);
        ptrlist_free(sym_opts);
    }

    return results;
}

static ptrlist_t *
bsr_build_symbol(bsr_ctx_t *ctx, n00b_match_t *match,
                 int32_t left, int32_t right)
{
    ptrlist_t *results = ptrlist_new();

    switch (match->kind) {
    case N00B_MATCH_EMPTY: {
        if (left == right) {
            n00b_nt_node_t *pn = new_epsilon_node();

            pn->start = left;
            pn->end   = left;

            n00b_parse_tree_t *t = n00b_tree_node(n00b_nt_node_t,
                                                    n00b_token_info_t *, *pn);

            n00b_free(pn);
            ptrlist_push(results, t);
        }
        break;
    }

    case N00B_MATCH_TERMINAL:
    case N00B_MATCH_ANY:
    case N00B_MATCH_CLASS:
    case N00B_MATCH_SET: {
        if (right == left + 1) {
            n00b_parse_tree_t *t = bsr_make_token_node(ctx->parser, left);

            ptrlist_push(results, t);
        }
        break;
    }

    case N00B_MATCH_NT: {
        ptrlist_t *nt_trees = bsr_build_nt(ctx, match->nt_id, left, right);

        ptrlist_extend(results, nt_trees);
        ptrlist_free(nt_trees);
        break;
    }

    case N00B_MATCH_GROUP: {
        n00b_rule_group_t *grp = (n00b_rule_group_t *)match->group;

        if (grp) {
            ptrlist_t *grp_trees = bsr_build_group(ctx, grp, left, right);

            ptrlist_extend(results, grp_trees);
            ptrlist_free(grp_trees);
        }
        break;
    }

    default:
        break;
    }

    return results;
}

static ptrlist_t *
bsr_build_group(bsr_ctx_t *ctx, n00b_rule_group_t *grp,
                int32_t left, int32_t right)
{
    ptrlist_t      *results = ptrlist_new();
    n00b_grammar_t *g       = ctx->parser->grammar;
    n00b_nonterm_t *gnt     = n00b_get_nonterm(g, grp->contents_id);

    if (!gnt) {
        return results;
    }

    // Empty group: left == right and min == 0.
    if (left == right && grp->min == 0) {
        n00b_nt_node_t pn = {0};

        pn.id        = N00B_GROUP_ID;
        pn.start     = left;
        pn.end       = right;
        pn.name      = gnt->name;
        pn.group_top = true;

        n00b_parse_tree_t *t = n00b_tree_node(n00b_nt_node_t,
                                                n00b_token_info_t *, pn);

        ptrlist_push(results, t);

        return results;
    }

    // Non-empty group: build via content NT's rules.
    if (n00b_list_len(gnt->rule_ids) > 0) {
        int32_t            rule_ix = gnt->rule_ids.data[0];
        n00b_parse_rule_t *rule    = n00b_get_rule(g, rule_ix);

        if (!rule) {
            return results;
        }

        int32_t rule_len      = (int32_t)n00b_list_len(rule->contents);
        int32_t complete_slot = g->lr0_rule_item_base[rule_ix] + rule_len;

        uint64_t     key = ((uint64_t)(uint32_t)complete_slot << 32)
                         | (uint64_t)(uint32_t)right;
        bsr_pair_list_t *b  = bsr_index_find(&ctx->index, key);

        if (b) {
            for (size_t i = 0; i < b->len; i++) {
                if (b->data[i].left != left) {
                    continue;
                }

                ptrlist_t *inner = bsr_build_rule(ctx, rule_ix, left, right);
                size_t     n     = ptrlist_len(inner);

                for (size_t j = 0; j < n; j++) {
                    n00b_parse_tree_t *inner_t = ptrlist_get(inner, j);

                    n00b_nt_node_t pn = {0};

                    pn.id        = N00B_GROUP_ID;
                    pn.start     = left;
                    pn.end       = right;
                    pn.name      = gnt->name;
                    pn.group_top = true;

                    if (!n00b_tree_is_leaf(inner_t)) {
                        n00b_nt_node_t *inner_pn = &n00b_tree_node_value(inner_t);
                        pn.penalty = inner_pn->penalty;
                        pn.cost    = inner_pn->cost;
                    }

                    n00b_parse_tree_t *t = n00b_tree_node(
                        n00b_nt_node_t, n00b_token_info_t *, pn);

                    (void)n00b_tree_add_child(t, inner_t);
                    ptrlist_push(results, t);
                }

                ptrlist_free(inner);
                break;
            }
        }
    }

    return results;
}

static ptrlist_t *
build_bsr_forest(n00b_earley_parser_t *p)
{
    if (!p->bsr_set || p->bsr_count == 0) {
        return ptrlist_new();
    }

    bsr_ctx_t ctx = {
        .parser = p,
    };

    bsr_build_index(p, &ctx.index);
    bsr_memo_init(&ctx.memo);

    p->grammar->suspend_penalty_hiding++;

    ptrlist_t *results = bsr_build_nt(&ctx, p->start, 0,
                                       p->current_state->id);

    p->grammar->suspend_penalty_hiding--;

    bsr_index_free(&ctx.index);

    return results;
}

// ============================================================================
// Tree intermediate cleanup
// ============================================================================

void
n00b_earley_cleanup_intermediates(n00b_earley_parser_t *p)
{
    size_t n_infos = n00b_list_len(p->tree_nb_infos);

    for (size_t i = 0; i < n_infos; i++) {
        nb_info_t *ni = n00b_list_get(p->tree_nb_infos, i);

        if (!ni) {
            continue;
        }

        n00b_free(ni->pnode);

        if (ni->opts) {
            ptrlist_free(ni->opts);
        }

        n00b_free(ni);
    }

    size_t n_ptrlists = n00b_list_len(p->tree_ptrlists);

    for (size_t i = 0; i < n_ptrlists; i++) {
        ptrlist_t *pl = n00b_list_get(p->tree_ptrlists, i);

        if (pl) {
            for (size_t j = 0; j < ptrlist_len(pl); j++) {
                ptrlist_t *inner = ptrlist_get(pl, j);

                if (inner) {
                    ptrlist_free(inner);
                }
            }

            ptrlist_free(pl);
        }
    }

    n00b_list_free(p->tree_nb_infos);
    n00b_list_free(p->tree_ptrlists);
}

// ============================================================================
// Group normalization: collapse group_item wrappers into group_top
// ============================================================================

// After earley tree construction, group_top nodes may contain group_item
// wrapper children (an earley-specific artifact). This pass promotes
// each group_item's children into the group_top directly, making earley
// trees structurally match PWZ trees (group_top → content NTs).
static void
normalize_groups(n00b_parse_tree_t *t)
{
    if (!t || n00b_tree_is_leaf(t)) {
        return;
    }

    // Recurse into children first (bottom-up).
    size_t nc = n00b_tree_num_children(t);

    for (size_t i = 0; i < nc; i++) {
        normalize_groups(n00b_tree_child(t, i));
    }

    n00b_nt_node_t *pn = &n00b_tree_node_value(t);

    if (!pn->group_top) {
        return;
    }

    // Check if any children are group_item wrappers.
    bool has_group_items = false;

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_tree_child(t, i);

        if (!n00b_tree_is_leaf(child)
            && n00b_tree_node_value(child).group_item) {
            has_group_items = true;
            break;
        }
    }

    if (!has_group_items) {
        return;
    }

    // Count the total children after splicing.
    size_t new_count = 0;

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_tree_child(t, i);

        if (!n00b_tree_is_leaf(child)
            && n00b_tree_node_value(child).group_item) {
            new_count += n00b_tree_num_children(child);
        }
        else {
            new_count++;
        }
    }

    // Build a new children array.
    n00b_parse_tree_t **new_children
        = n00b_alloc_array(n00b_parse_tree_t *, new_count);
    size_t out = 0;

    for (size_t i = 0; i < nc; i++) {
        n00b_parse_tree_t *child = n00b_tree_child(t, i);

        if (!n00b_tree_is_leaf(child)
            && n00b_tree_node_value(child).group_item) {
            // Splice group_item's children into the parent.
            size_t gc = n00b_tree_num_children(child);

            for (size_t j = 0; j < gc; j++) {
                new_children[out++] = n00b_tree_child(child, j);
            }
        }
        else {
            new_children[out++] = child;
        }
    }

    n00b_tree_replace_children(t, new_children, new_count);
}

// ============================================================================
// Public API: n00b_earley_get_forest
// ============================================================================

n00b_parse_forest_t
n00b_earley_get_forest(n00b_earley_parser_t *p)
{
    ptrlist_t *forest;

    bool use_bsr = p->bsr_set && p->bsr_count > 0;

    if (use_bsr) {
        forest = build_bsr_forest(p);

        if (ptrlist_len(forest) == 0) {
            ptrlist_free(forest);
            forest = build_forest(p);
        }

        forest = score_filter(forest);
    }
    else {
        forest = score_filter(build_forest(p));
    }

    forest = clean_trees(forest);

    // Sort the forest deterministically so that ambiguous parses with
    // equal penalty/cost always produce the same "best" tree at index 0.
    sort_trees(forest, n00b_get_disambiguator(p->grammar));

    // Normalize group_item wrappers out of the trees so earley trees
    // structurally match PWZ trees (group_top → content NTs directly).
    int32_t count = (int32_t)ptrlist_len(forest);

    for (int32_t i = 0; i < count; i++) {
        normalize_groups(ptrlist_get(forest, i));
    }

    n00b_parse_tree_array_t trees = n00b_array_new(n00b_parse_tree_ptr_t,
                                                    count ? count : 1);

    for (int32_t i = 0; i < count; i++) {
        n00b_array_set(trees, i, ptrlist_get(forest, i));
    }

    trees.len = (size_t)count;

    ptrlist_free(forest);
    n00b_earley_cleanup_intermediates(p);

    return n00b_parse_forest_new(p->grammar, trees);
}

